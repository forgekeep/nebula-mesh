# Production readiness

This document defines what must be true before nebula-mesh is described as
production-ready. It separates project readiness from deployment readiness and
keeps the decision independent of the major version number.

The current project status is **Beta**. Several foundations are already in
place, but the required gates below are not all complete.

## Readiness is not a `v1.0.0` milestone

nebula-mesh may remain on the `0.x` release line indefinitely. A release below
`v1.0.0` can be production-ready, and publishing `v1.0.0` would not by itself
make the project production-ready.

The `0.x` release policy is:

- `0.MINOR.0` may contain breaking API, CLI, configuration, or storage changes.
- `0.MINOR.PATCH` releases must not intentionally introduce breaking changes.
- Every known breaking change must be called out in the release notes with an
  upgrade procedure and, where possible, a rollback procedure.
- Security fixes target the latest tagged release, as defined in
  [SECURITY.md](../SECURITY.md).
- The version number is not a substitute for the compatibility and validation
  evidence required below.

This policy removes `v1.0.0` as an arbitrary readiness gate. It does not remove
the need to define and test compatibility between the management server,
agents, database schema, configuration files, and public API.

## Supported production scope

The initial production-ready scope is intentionally narrow:

- one `nebula-mgmt` instance backed by local SQLite;
- agent-managed Linux, macOS, FreeBSD, and Windows hosts supported by the
  published build matrix;
- TLS terminated by `nebula-mgmt` or a supported reverse proxy;
- recovery through a tested backup and cold-standby procedure;
- mobile hosts managed through manual bundle generation and re-import.

Active-active control-plane HA is not required for this scope. A reliable,
tested restore procedure is required. Automatic mobile bundle delivery is also
not required while the manual lifecycle and its limitations remain explicit.

## Current baseline

The following capabilities already exist and should not be reimplemented as
part of the readiness work:

- PR CI runs `go vet`, `go build`, `go test -race`, `golangci-lint`, `gosec`,
  and `govulncheck` ([CI workflow](../.github/workflows/ci.yml)).
- Deterministic fleet simulations cover token single-use, IP uniqueness,
  tenant isolation, configuration convergence, revocation, certificate
  renewal, and blocklist propagation (`internal/simtest`).
- The nightly workflow runs bounded generative fuzzing for `FuzzGenerate` and
  `govulncheck` ([scheduled workflow](../.github/workflows/scheduled.yml)).
- The server provides `/healthz`, `/readyz`, `/metrics`, structured logs, audit
  records, certificate-expiry alerts, and lifecycle webhooks.
- Backup and restore use a consistent SQLite snapshot, verify the master key,
  and migrate older snapshots forward ([backup guide](backup.md)).
- The security model and accepted residual risks are documented in the
  [threat model](security/threat-model.md).
- Mobile enrollment, certificate rotation, revocation, and the manual update
  procedure are documented in the [server guide](server.md#mobile-hosts-ios--android).

## Required gates

### 1. Release and compatibility contract

- [ ] Publish a compatibility matrix for `nebula-mgmt`, `nebula-agent`, the
  database schema, and supported upstream Nebula versions.
- [ ] Define the rolling-upgrade window. At minimum, the supported server must
  accept agents from the previous supported minor release while agents are
  upgraded.
- [ ] Add mixed-version integration tests for enrollment, polling,
  configuration rollout, certificate renewal, and revocation.
- [ ] For each incompatible database migration, test upgrade from the previous
  supported release and rollback by restoring a pre-upgrade backup.
- [ ] Require release notes to identify breaking changes, required operator
  actions, irreversible migrations, and rollback constraints.

Completion of this gate makes the `0.x` release policy predictable enough for
production use without freezing the project at `v1.0.0`.

### 2. End-to-end and scale validation

- [ ] Complete Tier 3 from
  [ADR 0009](adr/0009-scale-and-fuzz-testing.md): load generated artifacts into
  real `nebula.Control` instances and prove that a host and lighthouse form a
  tunnel.
- [ ] Exercise certificate renewal, revocation, firewall changes, and CA
  rotation through the Tier 3 data path.
- [ ] Add an OS-level test for package installation, systemd startup, atomic
  file replacement, `SIGHUP`, and a real TUN device. This may run as a
  scheduled or release-candidate job rather than on every PR.
- [ ] Run every checked-in fuzz target in the scheduled workflow and retain
  minimized crashers as fast regression tests.
- [ ] Add a long-running, high-fan-out fleet simulation using a documented
  target size. Measure poll load, SQLite contention, configuration convergence,
  and blocklist amplification instead of relying on the current small scale
  smoke test.

### 3. Security qualification

- [ ] Complete an independent assessment of CA key handling, authorization
  boundaries, enrollment, proof-of-possession polling, replay protection,
  revocation propagation, OIDC/TOTP, CSRF/SSRF defenses, and mobile bundles.
- [ ] Resolve all confirmed Critical and High findings affecting the supported
  release before declaring it production-ready.
- [ ] Keep `gosec`, `govulncheck`, dependency review, and the race detector as
  required release checks.
- [ ] Sign release artifacts and container images, and publish an SBOM and
  build provenance. The current release pipeline publishes SHA-256 checksums
  but does not provide an artifact-signing contract.
- [ ] Document a security-release response target so operators know how quickly
  they must update when only the latest tag receives fixes.

### 4. Upgrade, backup, and recovery

- [ ] Add an automated acceptance test that backs up a populated control plane,
  restores it on a clean instance, verifies every CA can be decrypted, and
  completes an agent poll and disposable certificate issuance.
- [ ] Test restore from every supported schema version to the current release.
- [ ] Publish a release rollback runbook that pairs the previous binary with a
  pre-upgrade database snapshot. Do not imply that an older binary can open a
  schema migrated by a newer release unless that path is tested.
- [ ] Define expected control-plane behavior during an outage and verify it in
  an end-to-end test. Cover enrollment, renewal, configuration rollout, and
  revocation while the server is unavailable.
- [ ] Document a cold-standby recovery exercise with measurable RPO and RTO;
  operators choose their own targets, but the procedure must expose how to
  verify them.

### 5. Operations and observability

- [ ] Publish a minimal production alert set for readiness failures, HTTP error
  rate, failed enrollment and renewal, CA and host certificate expiry, stale
  agents, and failed webhook delivery.
- [ ] Expose enough state to distinguish the desired configuration version
  from the last version applied by each agent, or document another reliable
  convergence check.
- [ ] Expose or document a reliable way to alert on stale backups.
- [ ] Run a release-candidate soak that includes restart, upgrade, restore,
  revocation, CA rotation, and loss of one lighthouse or relay. Record the
  tested topology, duration, and acceptance thresholds.

### 6. Mobile lifecycle

- [x] Document that mobile clients do not run `nebula-agent` and require manual
  bundle re-import after certificate rotation or topology changes.
- [ ] Add an end-to-end test that validates a generated mobile bundle with the
  supported upstream Nebula configuration parser and confirms that peer
  revocation reaches agent-managed peers.
- [ ] Verify expiry warnings cover the manual lead time required to rotate a CA
  and re-import all affected mobile bundles.
- [ ] Include the manual mobile lifecycle in the release-candidate soak and
  recovery runbook.

Automatic mobile renewal and configuration delivery would improve the product,
but it is not a blocker for the initial scope when the manual contract is
explicit and tested.

## Deployment readiness

A production-ready project can still be deployed unsafely. Operators should not
treat the project declaration as approval of a particular installation. A
deployment must separately provide:

- TLS and access control for the management API and UI;
- protected storage for `NEBULA_MGMT_MASTER_KEY`, separate from database
  backups;
- deny-by-default Nebula firewall rules appropriate to the environment;
- tested backup retention and cold-standby recovery;
- monitoring and alert delivery independent of the failed component;
- redundant lighthouses and relays where availability requires them;
- an independent break-glass path for management access.

The [deployment guide](deployment.md), [backup guide](backup.md), and
[security policy](../SECURITY.md) define the current operational baseline.

## Declaring production readiness

The project may replace the Beta label with a scoped production-ready statement
when all unchecked items under **Required gates** are complete or explicitly
moved to **Non-goals** with a documented rationale and compensating control.

The declaration must identify:

1. the exact supported scope;
2. the first qualified release;
3. the compatibility and security-support policy;
4. links to the qualification evidence;
5. known limitations that remain operator responsibilities.

The declaration is a maintenance commitment, not a one-time release event.
