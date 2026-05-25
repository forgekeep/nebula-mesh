# ADR 0008 — Hybrid CA rotation

- **Status**: Accepted
- **Date**: 2026-05-15
- **Context**: Issue [#110](https://github.com/forgekeep/nebula-mesh/issues/110) — *CA rotation flow for auto-provisioned CAs*.

## Context

Per ADR 0007 and issue #114, the codebase auto-provisions per-operator CAs with a 10-year lifetime to avoid the complexity of early rotation. However, this defers the rotation problem rather than solving it: `pki/signer.go` refuses to sign host certificates after the CA's `NotAfter` timestamp, causing the mesh to silently break on the day the CA expires.

The PKI layer already provides primitives for rotation:

- `pki.NewRotation(oldCA, newName, duration)` — creates a rotation envelope with both old and new CA instances.
- `(*Rotation).TrustBundle()` — returns the concatenated PEM bytes of the old and new CA certificates.

What was missing: storage persistence (database row for the new CA), REST/CLI/Web UI entry points, and the agent-side trust bundle distribution.

## Decision

Implement **Option C: Hybrid CA rotation** — operators can manually rotate CAs via the UI, REST API, or CLI; an optional background worker can automate rotation for approaching-expiry CAs.

### Warning badge

When a CA's remaining lifetime falls to ≤20% (using the same renewal threshold as host certificates), the UI displays a warning badge:

- `cas_list.html` table — "⚠ Expires soon" badge after the CA status.
- `ca_detail.html` — "⚠ Expires soon" badge in the page header.
- `profile.html` "My Certificate Authorities" card — same badge.

The threshold is computed using the existing `pki.ShouldRenew(notBefore, notAfter)` pattern, checking if `(notAfter - now) / (notAfter - notBefore) <= 0.20`.

Handlers pre-compute `IsExpiringSoon bool` for the CA to avoid template-side logic.

### Manual rotation (UI, REST, CLI)

A **Rotate** button appears on `ca_detail.html` (adjacent to Retire). Clicking it:

1. Issues a `POST /api/v1/cas/{id}/rotate` request to the REST API.
2. Server calls `pki.RotateAndStoreCA(ctx, store, master, logger, oldCA)`.
3. A new CA is generated with the same lifetime duration as the old CA.
4. The new CA is sealed via the master key and persisted to the database with `predecessor_id = oldCA.ID`.
5. An audit entry `ca.rotated` is recorded.
6. The new CA is returned in the response.

**CLI parity**: `nebula-mgmt ca rotate <id>` invokes the same REST endpoint and prints the new CA's details.

**Ownership gating**: Only the CA's owner (the operator who provisioned it) or an admin can rotate it.

**Idempotency**: If a rotation already exists (i.e., the CA has a successor), the endpoint returns the existing successor without creating a duplicate.

### Storage schema

A new column `cas.predecessor_id` is added (migration 015):

```sql
ALTER TABLE cas ADD COLUMN predecessor_id TEXT REFERENCES cas(id) ON DELETE SET NULL;
```

After rotation, the `cas` table contains two rows:

- **Old CA**: `status = 'active'`, `predecessor_id = NULL`. Any host certificates signed by the old CA remain valid until their natural expiry.
- **New CA**: `status = 'active'`, `predecessor_id = oldCA.ID`. Same owner, same lifetime duration as the old CA, new key material.

The old CA retains `status = 'active'` explicitly — this allows existing host certificates (signed by the old CA) to be verified successfully during renewal and mesh operations. The operator may later retire the old CA when all dependent host certificates have naturally expired or been renewed.

### Trust bundle distribution

When an agent polls `/api/v1/agents/{id}/updates`, it receives:

```json
{
  "host_updates": { ... },
  "ca_cert_pem": "<old-ca-cert>\\n<new-ca-cert>"
}
```

The `ca_cert_pem` field contains a multi-cert PEM block (both the old and new CA certificates concatenated with newlines). This **trust bundle** is returned when:

- The host's CA (`host.ca_id`) exists in the database.
- That CA has a successor (i.e., another CA with `predecessor_id = host.ca_id`).

The agent's existing PEM parser (used by Nebula) natively handles multi-cert PEM files, so no agent-side code changes are required. On the next poll, the agent atomically writes the trust bundle to disk, overwriting the previous single-cert PEM.

**Depth limit**: The trust bundle contains at most two CA certificates (old + new). Deeper chains (old → new → newer) are not supported; they become a follow-up task if needed.

**Existing host certificates**: Certificates signed by the old CA before rotation remain valid until their natural expiry, because the old CA stays `active` and is included in the trust bundle during renewal window.

### Opt-in auto-rotate worker

A background scanner (`internal/cawatch/scanner.go`) can be enabled to automatically rotate approaching-expiry CAs. Configuration in `server.yaml`:

```yaml
ca_auto_rotate:
  enabled: true            # default false
  interval: 6h             # default 6h, how often to check
  threshold: 0.20          # default 0.20 (20% remaining)
```

The scanner:

1. Runs once per `interval` (in a separate goroutine).
2. Queries `store.ListCAsApproachingExpiry(ctx, threshold)` to fetch CAs with ≤threshold% lifetime remaining.
3. For each CA, calls `pki.RotateAndStoreCA`.
4. Records an audit entry `ca.auto_rotated` with the new CA ID.
5. Logs the event.

If an error occurs (e.g., database transient failure), the scanner logs the error and skips to the next check interval without blocking shutdown.

The scanner is opt-in (disabled by default) to avoid surprises in existing deployments. When enabled, rotation is fully automatic and audited.

### Shared implementation

The canonical rotation logic lives in `pki.RotateAndStoreCA`:

```go
func RotateAndStoreCA(
    ctx context.Context,
    store Store,
    master *keystore.Master,
    logger *slog.Logger,
    oldCA *models.CA,
) (*models.CA, error)
```

This helper:

1. Creates a new CA using `pki.NewCA` with the same `NotAfter - NotBefore` duration as the old CA.
2. Seals the new CA's key material via the master key.
3. Persists the new CA to the database with `predecessor_id = oldCA.ID`.
4. Records an audit entry `ca.rotated`.
5. Returns the new CA.

Every code path (Web UI, REST API, CLI, auto-rotate worker) calls this shared helper, ensuring a single source of truth for rotation semantics.

## Consequences

### Positive

- **Mesh does not silently break**: The warning badge alerts the operator before a CA expires.
- **Explicit by default**: Manual rotation via UI/REST/CLI is the primary flow; automation is opt-in.
- **Existing host certificates remain valid**: The old CA stays `active`, so certificates signed before rotation continue to verify and function.
- **Single source of truth**: `pki.RotateAndStoreCA` is shared across all rotation entry points.
- **Idempotent rotation**: Rotating a CA that already has a successor is a no-op; no duplicate successors are created.
- **Trust bundle is automatic**: No agent re-enrollment needed; the next poll delivers the new CA to the agent.
- **Audit trail**: Both manual and auto rotations are logged and audited.

### Breaking changes

- **New migration 015**: Adds the `predecessor_id` column. Rollback is supported (migration `.down.sql` drops the column).
- **Agent updates API semantics change**: The `ca_cert_pem` field may now contain multiple PEM blocks (trust bundle) instead of a single certificate. The Nebula client natively parses multi-cert PEM, so client-side code is unaffected, but non-Nebula parsers must handle multi-cert PEM.
- **New REST endpoint**: `POST /api/v1/cas/{id}/rotate`. Existing clients are unaffected; new tooling can use this endpoint.

### Operational migration

**For existing deployments:**

1. All existing CAs (without a successor) continue to function normally. The `predecessor_id` column is nullable; old CAs have `NULL` in this field.
2. When a CA approaches its expiry and a warning badge appears, the operator can manually click **Rotate** or (if enabled) the auto-rotate scanner will rotate it automatically.
3. The new CA is delivered to agents on the next poll.
4. Existing host certificates signed by the old CA remain valid until their natural expiry.

**For new deployments:**

- Optional: Set `ca_auto_rotate.enabled: true` to enable automatic rotation. Leave disabled by default to maintain explicit operator control.

## Related ADRs

- **ADR 0007** — Removed legacy on-disk CA stack and established per-operator CAs in the database.
- **ADR 0002** — Introduced per-operator CA model.

## Implementation notes

- Migration 015: `internal/store/migrations/015_ca_predecessor.up.sql` and `.down.sql`.
- Core helper: `internal/pki/rotation_store.go::RotateAndStoreCA`.
- Storage query: `store.Store.ListCAsApproachingExpiry(ctx, threshold) ([]*models.CA, error)`.
- Models: `models.CA.PredecessorID *string` field added.
- API: `api.handleRotateCA` handler and `POST /api/v1/cas/{id}/rotate` route.
- Web: `web.handleCARotate` handler, Rotate button in templates, warning badge in `cas_list.html`, `ca_detail.html`, `profile.html`.
- CLI: `cli.CARotate(serverURL, apiKey, id)` function and `rotate` subcommand in `nebula-mgmt ca`.
- Auto-rotate: `internal/cawatch/scanner.go` (new package) with opt-in `ca_auto_rotate` config.
- Tests: Unit tests for rotation logic, integration tests for UI/API/CLI flows, and auto-rotate scanner behavior.

## References

- Issue: <https://github.com/forgekeep/nebula-mesh/issues/110>
- Related issues: [#102](https://github.com/forgekeep/nebula-mesh/issues/102) (10-year CA lifetime), [#114](https://github.com/forgekeep/nebula-mesh/issues/114) (consolidate CA mint).
- Related PR: [#113](https://github.com/forgekeep/nebula-mesh/pull/113) (admin auto-provision CA).
