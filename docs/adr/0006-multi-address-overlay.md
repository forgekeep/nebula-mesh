# ADR 0006 — Multiple overlay addresses per network and per host

- **Status**: Accepted
- **Date**: 2026-05-14
- **Tracking issue**: [#108](https://github.com/juev/nebula-mesh/issues/108)
- **Depends on**: [ADR 0004 — Agent authorization model](0004-agent-authorization.md)
- **Related**: [ADR 0001 — CA key storage](0001-ca-key-storage.md), [ADR 0005 — Pre-auth keys](0005-pre-auth-keys.md)

## 1. Context

Today's architecture constrains each network to a single CIDR (`networks.cidr` column) and each host to a single overlay address (`hosts.nebula_ip` column). This single-address design is sufficient for simple deployments but blocks:

- **Dual-stack networks** — operators wanting to deploy IPv4 and IPv6 simultaneously must run parallel mesh networks, doubling administrative overhead and cert complexity.
- **Segmented address plans** — assigning hosts to logically isolated subnets within the same Nebula overlay (e.g., `10.42.0.0/24` for general workloads, `10.42.1.0/24` for sensitive services) requires multiple separate networks today.

Our Nebula library (`slackhq/nebula` v1.10.3) already ships with cert format version 2, which defines `certificate.TBSCertificate{Version: cert.Version2, Networks: []netip.Prefix}`. The cert signer in `internal/pki/signer.go` already accepts multi-prefix input; callers throughout the codebase (`enroll.go`, `mobilebundle/builder.go`, `updates.go`) currently pass single-element slices and convert them back to strings at the API boundary.

This ADR makes the architectural decision explicit: **support multiple CIDR prefixes per network and multiple overlay addresses per host, stored in normalized tables, with atomic replacement semantics**.

## 2. Decision

We adopt the following architecture:

### 2.1 Schema: Normalized tables for multi-address support

Replace single-column storage with normalized, position-ordered tables:

- **`network_cidrs(network_id, position, cidr)`** — replaces `networks.cidr`. Stores each CIDR as a separate row with an explicit position (0-indexed). No duplicates or overlaps within a network allowed.
- **`host_addresses(host_id, position, address)`** — replaces `hosts.nebula_ip`. Stores each overlay address as a separate row with an explicit position. Every address must belong to one of the parent network's CIDRs. No duplicates within a host allowed.

The `networks.cidr` and `hosts.nebula_ip` columns are dropped after the backfill (not nullable; clean break). Cascading deletes on foreign keys ensure consistency.

**Position semantics:** The position field enforces ordering. When a cert is signed, prefixes are taken in position order; when configgen emits config, addresses are taken in position order. Reordering the API request PATCH payload changes the cert and config without re-signing (new cert issued with reordered `Networks[]`).

### 2.2 One-shot backfill migration

Migration 014 (`internal/store/migrations/014_multi_address.up.sql`) performs an atomic backfill:

1. Create the new `network_cidrs` and `host_addresses` tables.
2. Copy existing data: `INSERT INTO network_cidrs SELECT id AS network_id, 0 AS position, cidr FROM networks WHERE cidr IS NOT NULL`.
3. Drop old columns via table recreation (due to SQLite FK constraint handling): `ALTER TABLE networks RENAME TO networks_old; CREATE TABLE networks(...); INSERT INTO networks SELECT ... FROM networks_old; DROP TABLE networks_old`.

The down migration (`014_*.down.sql`) reverses the table creation and restores the old columns. **Important:** rollback recovers only position=0 rows; multi-address rows are lost. Operators must back up the database before running migration 014 in production.

### 2.3 API: Clean-break approach with strict validation

The API adopts a **strict clean break**:

- **Field names change**: `cidr` → `cidrs` (array), `nebula_ip` → `nebula_ips` (array).
- **Rejection of legacy fields**: Any request containing `cidr` or `nebula_ip` (singular) receives a 400 Bad Request with a message pointing to the new field names.
- **Strict deserialization**: `json.Decoder` is configured with `DisallowUnknownFields` to catch migration mistakes early.
- **Request format**: `POST /api/v1/networks` and `POST /api/v1/hosts` expect `cidrs: [...]` and `nebula_ips: [...]` as arrays of strings. PATCH `/api/v1/hosts/{id}` replaces the entire `nebula_ips` list atomically.
- **Response format**: Responses include the full list in declared order: `"cidrs": ["10.42.0.0/24", "fd00:42::/64"]`, `"nebula_ips": ["10.42.0.10", "fd00:42::10"]`.

### 2.4 One v2 certificate per host

Each host receives **exactly one certificate per enrollment/rotation**, signed with the complete set of overlay addresses from all parent CIDRs. The cert version is always 2 (`Version: cert.Version2`), and the `Networks[]` field contains all prefixes in position order.

Example: a host on a network with CIDRs `["10.42.0.0/24", "fd00:42::/64"]` and addresses `["10.42.0.10", "fd00:42::10"]` receives a cert with `Networks: [netip.PrefixFrom(10.42.0.10/32), netip.PrefixFrom(fd00:42::10/128)]` — one /32 and one /128 for the two families.

### 2.5 Configgen: Multiple static_host_map entries per overlay-IP

The config generator (`internal/configgen/`) changes to emit:

- **`static_host_map`**: One entry per overlay-IP of each lighthouse. Example:
  ```yaml
  static_host_map:
    "10.42.0.10": ["1.2.3.4:4242"]
    "fd00:42::10": ["1.2.3.4:4242"]
    "10.42.0.11": ["1.2.3.5:4243"]
    "fd00:42::11": ["1.2.3.5:4243"]
  ```
- **`lighthouse.hosts`**: All overlay addresses of all lighthouses. Example:
  ```yaml
  lighthouse:
    hosts:
      - "10.42.0.10"
      - "fd00:42::10"
      - "10.42.0.11"
      - "fd00:42::11"
  ```
- **`unsafe_routes` family matching**: Each unsafe route's `via` address must belong to the same address family as the route's `remote` prefix. If a route uses IPv4 and specifies an IPv6 `via`, the server rejects it with a clear error message. This prevents silent misconfigurations.

### 2.6 Soft limit on addresses per host

A soft limit of **16 addresses per host** (`MaxAddressesPerHost = 16` in `internal/models/`) prevents certificate size blow-up. Operators hitting this limit receive a clear error message and must split their deployment across multiple networks.

### 2.7 Web UI: Repeatable rows for multi-address input

The form state and templates change to support repeatable rows:

- **Network form** (`templates/networks.html`): Each CIDR appears in its own row with an add/remove button. A dropdown selects which CIDR to assign to a new host (visible only if the network has >1 CIDR).
- **Host form** (`templates/host_new.html`, `templates/host_edit.html`): Each overlay address appears in its own row with add/remove buttons and per-row inline error messages. Each row includes a dropdown to select the parent CIDR from the network's CIDR list.
- **Form state** (`internal/web/form_state.go`): `NetworkFormState.CIDRs []string` and `HostFormState.NebulaIPs []string` store the slices. Per-row validation errors are collected in `[]error` for rendering.
- **JavaScript**: Vanilla JS (no framework) adds and removes rows by cloning the template row and updating indices.

The constrained-input widget from issue #100 (per-row CIDR-aware octet input) was removed due to multi-row refactor complexity. Server-side validation provides friendly, per-row error messages as the alternative UX. Re-implementation of the widget for multi-row context is tracked as a follow-up issue.

## 3. Validation rules

### 3.1 Network-level validation

Each network's CIDRs must satisfy:

1. **At least one CIDR** — empty networks are rejected.
2. **All parseable** — each string must parse as `netip.ParsePrefix()` without error.
3. **No duplicates** — no two CIDRs are identical.
4. **No overlaps** — no CIDR contains another (e.g., `10.0.0.0/8` overlaps with `10.42.0.0/24`).

Server-side validation function: `models.ValidateNetworkCIDRs(cidrs []string) error`.

### 3.2 Host-level validation

Each host's overlay addresses must satisfy:

1. **At least one address** — empty address lists are rejected.
2. **All parseable** — each string must parse as `netip.ParseAddr()` without error.
3. **All within parent CIDRs** — each address must fall within exactly one of the parent network's CIDRs (e.g., `10.42.0.10` is valid for `10.42.0.0/24`, invalid for `10.42.1.0/24`).
4. **IPv4 boundary check per CIDR** — if an address is the network address (e.g., `10.42.0.0` for `10.42.0.0/24`), it is rejected with a friendly error. (IPv6 network addresses are less common in practice but similarly rejected for consistency.)
5. **No duplicates within the host** — no two addresses are identical.
6. **Global uniqueness per network** — no two hosts on the same network can have the same address (enforced by the database unique constraint `UNIQUE(network_id, address)`).

Server-side validation function: `api.validateHostIPs(ips []string, network *models.Network) []error` (per-row errors for the form).

## 4. Consequences

### 4.1 Positive consequences

- **Dual-stack support**: Operators can provision networks with both IPv4 and IPv6 simultaneously, enabling modern deployments without parallel mesh networks.
- **Segmented address plans**: Assigning hosts to logical subnets within the same overlay is now straightforward.
- **No shim or dual-write complexity**: The clean break avoids maintaining two code paths or silent data-format drift. Every API client upgrades at once.
- **Position-based ordering preserved**: Cert and config generation respect the declared address order, enabling operators to control which family is tried first by reordering.
- **Atomic PATCH semantics**: Updating a host's address list is a single API call that atomically replaces the entire set and triggers a new cert issuance.

### 4.2 Negative consequences and trade-offs

#### 4.2.1 Migration rollback irreversibility

Rolling back migration 014 after multi-address rows have been created will recover only the position=0 address/CIDR (the last value before the new columns were dropped). Any additional addresses are permanently lost.

**Mitigation**: Operators must back up the database before running migration 014 in production. Release notes explicitly document this. A post-deployment recovery procedure should be written into the runbook.

#### 4.2.2 Breaking API change

Clients using the legacy `cidr` (singular) and `nebula_ip` (singular) fields will immediately receive 400 Bad Request responses. Legacy client integrations will break.

**Mitigation**: Error messages are clear and point to the new field names. A migration guide in the release notes or documentation explains the change and shows before/after examples.

#### 4.2.3 UX regression in Web UI

The constrained-input widget from issue #100 (per-CIDR octet segment validation, hex fields, etc.) has been removed. Users creating hosts now use plain text inputs with per-row validation errors from the server.

**Mitigation**: Server-side validation provides clear, inline error messages (e.g., "Address 10.42.0.0 is the network address and cannot be assigned"). A follow-up issue re-implements the constrained-input widget for multi-row contexts.

#### 4.2.4 Hard limit on addresses per host

The soft limit of 16 addresses per host (to prevent cert-size blow-up) may frustrate operators with unusually large address schemes.

**Mitigation**: The error message is explicit and suggests splitting across multiple networks. If real-world demand requires lifting the limit, it can be increased with a configuration parameter (currently hardcoded to keep the API simple).

#### 4.2.5 Family-match validation for unsafe_routes

Pre-existing configurations with IPv4 routes using IPv6 `via` addresses (or vice versa) will be rejected with a validation error. These configurations were never correct (Nebula would have failed at runtime), but operators may have disabled warnings.

**Mitigation**: The error message is explicit: "unsafe_route `via` address family must match route `remote` family." Operators apply the fix (correct the config or split the route) once per network, then proceed.

### 4.3 Schema migration notes for operators

For operators running this system in production:

1. **Prerequisite**: SQLite ≥3.35 is required for the `ALTER TABLE ... DROP COLUMN` support. The `modernc.org/sqlite` module pinned in `go.mod` (v1.48.0+) ships with compatible SQLite. Verify with `go.mod` + `go build ./cmd/nebula-mgmt` before upgrading.
2. **Backup database before migration**: `cp server.db server.db.backup` is the minimum. A versioned backup directory is recommended for production.
3. **Migration runs on next server start**: The embedded migration files in the binary are checked at startup; if migration 014 has not run, it is executed inside a transaction. No manual SQL is needed.
4. **Rollback**: Restoring from backup reverts all multi-address data to position=0. A full restore (host reprovision) is required to recover multi-address enrollments post-rollback.

## 5. References

- Tracking issue: [#108](https://github.com/juev/nebula-mesh/issues/108)
- Related issue (constrained-input widget): [#100](https://github.com/juev/nebula-mesh/issues/100)
- Mobile bundle feature (issue #107) — reference for multi-IP cert flow integration.
- Nebula certificate format: `github.com/slackhq/nebula/cert` — `certificate.TBSCertificate{Version: cert.Version2, Networks: []netip.Prefix}`.
- Implementation files:
  - Schema: `internal/store/migrations/014_multi_address.{up,down}.sql`
  - Models: `internal/models/{network,host,validate_ip}.go`
  - Store: `internal/store/sqlite.go` (CRUD methods updated)
  - API: `internal/api/{networks,hosts,validate_ip}.go` (DTOs, validation, handlers)
  - Configgen: `internal/configgen/generator.go` + template
  - Web: `internal/web/{form_state,handlers}.go` + `templates/{networks,hosts,dashboard}.html`
  - Tests: `internal/store/migration_014_test.go`, `internal/models/{network,host}_test.go`, `internal/api/networks_test.go` + fixtures, `internal/web/form_state_test.go`, integration tests in `tests/integration/`.
