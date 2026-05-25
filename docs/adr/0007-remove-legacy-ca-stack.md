# ADR 0007 — Remove legacy on-disk CA stack

- **Status**: Accepted
- **Date**: 2026-05-15
- **Context**: Issue [#114](https://github.com/forgekeep/nebula-mesh/issues/114) — *Consolidate CA mint logic and remove legacy on-disk CA stack*.

## Context

Before this change, the codebase maintained two parallel systems for CA management:

1. **Per-operator CAs in database** (ADR 0002) — the `cas` table, master keystore with envelope encryption, multi-CA endpoints `/api/v1/cas/*`, per-operator ownership isolation.
2. **Single on-disk CA** (legacy, ADR 0001 superseded) — `<data_dir>/ca.crt` and `<data_dir>/ca.key` encrypted with a passphrase, used as fallback in `api.Server.ca` for hosts without `ca_id`, for the CA rotation endpoint `POST /api/v1/ca/rotate`, and for mobile bundle generation fallback.

The mint-and-store logic was duplicated in exactly three places:

- `internal/web/cas.go::mintCAForOperator` — Web UI CA creation.
- `internal/api/cas.go::handleCreateCA` — REST API CA creation.
- (planned) `internal/cli/bootstrap_ca.go::ProvisionDefaultCAForOperator` — CLI admin CA provisioning.

Plus partially in `internal/cli/bootstrap_ca.go::ImportLegacyCAIfNeeded` — one-time migration from on-disk to database.

Since the project had no production deployments at the time of this change, a clean break became possible rather than a multi-release migration window. This decision trades a single breaking change for long-term code simplicity and architectural clarity.

## Decision

Remove the legacy on-disk CA stack entirely. The master keystore becomes **required** for both `nebula-mgmt init` and `nebula-mgmt serve`.

### Files deleted

**CA on-disk persistence:**
- `pki.LoadCA(certPath, keyPath, passphrase)` — function to decrypt and load CA from disk files.
- `(*pki.CAManager).Save(certPath, keyPath, passphrase)` — function to encrypt and save CA to disk files.
- `pki.defaultPassphrase` — private const used only by legacy on-disk CA.

**Server-side legacy CA adapter:**
- `api.CAConfig` struct — container for `CertPath`, `KeyPath`, `Passphrase`.
- `api.Server.ca` field — the fallback `*pki.CAManager` when no per-operator CA was set.
- `api.Server.caConfig` — config loading for legacy on-disk CA.
- `api.Server.caMu` — RWMutex protecting the legacy CA.
- `api.Server.handleGetCA` endpoint — GET `/api/v1/ca` (deprecated).
- `api.Server.handleRotateCA` endpoint — POST `/api/v1/ca/rotate` (deprecated).
- `internal/api/ca.go` — entire file containing the above endpoints.
- `api.singleCAResolver` adapter — translated legacy CA into multi-CA resolver interface.
- `api.caForHost` — fallback path that returned `s.ca` when host had no `ca_id`.

**CLI legacy CA import:**
- `cli.ImportLegacyCAIfNeeded` — one-time import of on-disk CA into the `cas` table.
- `cli.readCAPassphrase()` — prompt or env-var reader for CA passphrase.
- `caPassphraseEnv` const — the `NEBULA_MGMT_CA_PASSPHRASE` environment variable name.
- `internal/cli/bootstrap_ca.go` — entire file (CLI admin CA provisioning moved inline to `cli/init.go`).

**Database legacy migration:**
- `store.Store.BackfillCAID` — migration to assign `ca_id` to hosts without one.
- `sqlite_cas.go::BackfillCAID` impl.

**Operational artifacts:**
- `<data_dir>/ca.crt` and `<data_dir>/ca.key` — no longer created by `init` or loaded by `serve`.

### Consolidation

A new shared helper `pki.MintAndStoreCA` lives in `internal/pki/autoprovision.go` and implements the single canonical mint-and-store flow via a narrow `MintStore` interface (abstract the DB transaction). It is used by:

- `web/cas.go::mintCAForOperator` — Web UI wrapper that opens a transaction and calls the helper.
- `api/cas.go::handleCreateCA` — API wrapper (same pattern).
- `cli/init.go` — CLI init directly calls the helper to provision the admin-default CA.

The multi-CA endpoints `/api/v1/cas/*` remain the single REST API surface for CA management.

### API signature changes

`api.NewServer(s store.Store, apiKey string, logger *slog.Logger) *Server`

Changed from:
```go
NewServer(s store.Store, apiKey, caPassphrase string, caConfig *CAConfig, logger *slog.Logger) *Server
```

Now a 3-argument constructor.

## Consequences

### Positive

- **Single source of truth**: CA mint logic lives in one place (`pki.MintAndStoreCA`). Every path (Web, API, CLI) calls the same code.
- **Clear thread-safety model**: `CAResolver` uses no caching and has no shared mutable state. The `caMu` RWMutex disappears; no lock contention.
- **Simplified operator setup**: One master key secret (via env or config) instead of passphrase + master key combination.
- **Reduced attack surface**: No on-disk encrypted CA files as a secondary target. All CA material lives in the database under envelope encryption.
- **Architectural consistency**: All CA work now goes through the database + envelope encryption model. No dual paths.

### Breaking changes

**Deployment:**
- `nebula-mgmt init` and `nebula-mgmt serve` now fail immediately if `NEBULA_MGMT_MASTER_KEY` (or `master_key` in config) is not set.
- The legacy `NEBULA_MGMT_CA_PASSPHRASE` environment variable is removed; the passphrase prompt no longer appears.

**API:**
- Endpoints `GET /api/v1/ca` and `POST /api/v1/ca/rotate` are removed. External tooling must migrate to `/api/v1/cas/{id}/*` endpoints.
- CA rotation as a feature is temporarily absent. A single-CA endpoint deletion removes the only rotation API. Multi-CA rotation can be added in a follow-up as `POST /api/v1/cas/{id}/rotate` if needed.

**Database:**
- Existing databases with hosts lacking a resolvable `ca_id` become invalid. Startup validation in `serve` catches this and returns an error. (No production databases exist at release time; development environments can be recreated with `rm nebula.db`.)

**Backward compatibility:**
- No automatic migration from old to new. Deployers using the legacy on-disk CA must manually:
  1. Set `NEBULA_MGMT_MASTER_KEY`.
  2. Run `nebula-mgmt init` against a fresh database (or delete `nebula.db` and re-run).
  3. Delete the old `<data_dir>/ca.crt` and `<data_dir>/ca.key` files.

### Operational migration for dev environments

For developers with existing nebula-mesh databases:

1. Generate a fresh master key:
   ```bash
   export NEBULA_MGMT_MASTER_KEY=$(openssl rand -base64 32)
   ```

2. Delete the old database and re-initialize:
   ```bash
   rm /var/lib/nebula-mgmt/nebula.db
   nebula-mgmt init --config server.yml
   ```

3. The admin-default CA is now auto-provisioned and stored in the database.

4. Delete legacy on-disk files (if they exist):
   ```bash
   rm /var/lib/nebula-mgmt/ca.crt /var/lib/nebula-mgmt/ca.key
   ```

If you have a database with hosts/networks and want to preserve them, you must:

1. Export the existing data (REST API or direct DB queries).
2. Delete the DB.
3. Re-initialize with the new setup.
4. Re-create hosts/networks via API or UI.

## Related ADRs

- **ADR 0001** — superseded. Recommended storing CA keys on-disk encrypted. This ADR removes that decision entirely.
- **ADR 0002** — extended. Per-operator CAs are now the **only** CA model.
- **ADR 0003** — still valid. Explains encryption-at-rest threat model and alternatives considered.

## Implementation notes

- All deleted code (e.g. `LoadCA`, `Save`, `ImportLegacyCAIfNeeded`) is git-history searchable for future reference.
- Integration tests (`tests/integration/e2e_test.go`) are updated to set master key and verify admin-default CA auto-provisioning.
- Release notes must call out the breaking changes and migration path for any production deployments (none expected at this time).

## References

- Issue: <https://github.com/forgekeep/nebula-mesh/issues/114>
- Related PRs: [#113](https://github.com/forgekeep/nebula-mesh/pull/113), [#111](https://github.com/forgekeep/nebula-mesh/pull/111) (admin auto-provision, incorporated into init).
- Code: `internal/pki/autoprovision.go`, `internal/api/cas.go`, `internal/web/cas.go`, `internal/cli/init.go`.
