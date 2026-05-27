# ADR 0009 — Scale, concurrency, and fuzz testing

- **Status**: Proposed
- **Date**: 2026-05-25
- **Context**: The test suite has strong per-request unit coverage but no layer
  that exercises the control plane at fleet scale, under concurrency, or
  against adversarial input. The direction here (upstream all three tiers) is
  agreed; this ADR pins the specific CI-gating calls.

## Context

The repository's tests are predominantly table-driven unit tests plus an
in-process integration harness (`tests/integration/`) that stands up the real
API server behind `httptest.NewServer` over an in-memory SQLite store and signs
real proof-of-possession (PoP) polls (`signedGetUpdates`, ADR 0004). CI runs
`go test -race` and `golangci-lint`.

What this does **not** cover:

- **Fleet scale.** No test drives the control plane with thousands of hosts.
  The per-poll cost characteristics — `GetBlocklist` on every poll, the full
  blocklist shipped in every response, `has_updates` becoming permanently true
  once anything is blocked (`internal/api/updates.go`), config re-render
  fan-out on a network change — are unmeasured.
- **Concurrency correctness.** Single-request tests cannot exercise
  interleavings: concurrent enrollment-token redemption, multi-tenant
  isolation under simultaneous mutation, the cert-rotation overlap window
  (ADR 0004 §7.1), or the overlay-IP create/update race.
- **Config propagation.** Nothing asserts that one network change reaches
  *every* live host *exactly once* via the config-version counter
  (`GetNetworkConfigVersion` vs `GetHostConfigVersion`).
- **Adversarial input.** There was no fuzzing. The config generator was
  hardened against YAML-structure-break injection (GHSA-7hp6, issue #126) by
  marshaling a typed struct, but that guarantee was asserted only by
  hand-written cases — until `FuzzGenerate` (#155).
- **Realism.** No test confirms that the configs the control plane emits are
  actually loadable by — and form tunnels between — real `nebula` nodes.

A key property makes large-scale testing tractable: **the control plane never
observes "the network."** A host's generated config carries the lighthouse
roster, firewall rules, and relays — not a full peer map; Nebula's lighthouses
perform peer discovery. The server's entire interface to the world is *signed
HTTP polls and enroll requests*. Two agents and two hundred thousand agents are
indistinguishable to it except in volume and interleaving.

## Decision

Adopt a three-tier model and **upstream all three tiers**. Each tier proves a
different property on the substrate suited to it; scale, correctness, and
realism are not conflated. CI gates PRs on the fast subset only (see
[CI integration](#ci-integration-pr-gate-vs-scheduled)).

| Tier | Substrate | Proves | Realistic ceiling |
|------|-----------|--------|-------------------|
| **1 — Property / fuzz** | Pure functions via `go test` (+ `-fuzz`) | The math holds: configs always load, IPs never collide, PoP round-trips, migrations are total | unbounded inputs |
| **2 — In-process fleet sim** | N *virtual* agents (goroutines) vs the `httptest` server + SQLite | Scale, concurrency correctness, convergence, tenant isolation, revocation liveness, cert renewal — under `-race` | ~50k–500k virtual hosts |
| **3 — Nebula interop** | Real `nebula.Control` nodes (in-memory `e2e/router`); optionally a NixOS VM | The emitted config + signed cert actually form a tunnel; end-to-end systemd/SIGHUP/tun realism | ~tens of nodes (router); ~5–10 (VM) |

Real Nebula nodes are not run at scale. The synthetic fleet (Tier 2) proves
correctness at volume on a substrate the control plane cannot distinguish from
production; Tier 3 proves the artifacts it exercises are genuinely
Nebula-valid.

### Tier 1 — fuzzing and properties

Native Go fuzz targets, seeded from existing table tests. Seed corpora and
committed crashers run as ordinary `go test` on every PR; the generative
`-fuzz` pass runs on a schedule (see CI integration):

- **`FuzzGenerate`** (`internal/configgen/`, merged in #155) — random
  `GeneratorInput` → `Generate` → re-load through Nebula's own
  `config.C.LoadString`, then assert the scalars an agent reads
  (`am_lighthouse`, `punchy.punch`, `listen.port`) round-trip with type intact.
  It proves the control plane can never emit a config that bricks an agent's
  reload, and found the GHSA-7hp6 round-trip gap on its first run.
- **`FuzzPoPCanonical`** — `pop.CanonicalString` injectivity for
  separator-free inputs + sign/verify cross-check. (`CanonicalString` is an
  unescaped newline join; it is not a live auth bypass today — the one signed
  route pins method/path and the verifier rejects CR/LF, RFC3339-validates the
  timestamp, and caches nonces — but the framing is a latent fragility worth a
  guard and a future hardening.)
- **`FuzzValidateIP`** — random CIDR sets and address requests through
  `internal/api/validate_ip.go` and the multi-address path; assert no overlap
  or escape, dual-family.
- **`FuzzMigrations`** — apply all migrations to schema-plausible seed DBs;
  assert totality (no panic, no half-applied state).
- **`FuzzEnrollPayload` / `FuzzAgentUpdatesHeaders`** — malformed enroll bodies
  and PoP header combinations against the real handlers; assert the server
  never 500s and never issues a certificate on a malformed path.

### Tier 2 — the in-process fleet simulation

A *virtual agent* is a keypair plus a poll loop speaking the real enrollment +
PoP protocol against the real server, so the only thing virtualized is the
Nebula node the server never observes. The harness (`internal/simtest/`)
provides the agent, a multi-tenant helper, a controllable clock, and an event
journal. Invariants (named checkers, all run under `-race`):
config convergence, token single-use, IP-uniqueness (create/update),
revocation liveness, tenant isolation, blocklist scale, and cert renewal.

The harness is a **second layer over the per-fix targeted tests, not a
replacement.** Each hardening fix continues to ship its own race/property
tests; the simulation earns its place on the interleavings a single-feature
test won't reach — revocation racing renewal under load, that class of thing —
and each fix gains a Tier 2 invariant as it lands.

**Clock seam (implemented).** Cert renewal, the rotation overlap window, and
TTLs read time. Deterministic testing of those needs an injectable clock:
a `Server.WithClock(func() time.Time)` seam (default `time.Now`), a
`pki.ShouldRenewAt(notBefore, notAfter, now)` helper, and an optional
`SignRequest.Now`. Behavior is unchanged when the clock is unset; advancing
it lets the sim cross a cert's renewal window in milliseconds. The seam landed
in #170. (The `cawatch` / `alerts` background scanners
read `time.Now()` directly; seaming them is a follow-up for their
time-dependent invariants.)

### Tier 3 — Nebula interop

`slackhq/nebula` ships an in-process simulation under the `e2e_testing` build
tag: `e2e/router` wires real `nebula.Control` instances and shuttles packets
between them in memory (no UDP, no tun, no VM), with fine-grained drivers
(`RouteForAllUntilTxTun`, `InjectUDPPacket`). We reuse it as the interop check:
feed a config *our* control plane generates into a `nebula.Control`, stand up a
peer plus a lighthouse, and drive a handshake — asserting the emitted config +
signed cert genuinely form a tunnel. This is far stronger than `FuzzGenerate`'s
"the config loads in Nebula's parser" because it exercises the live data path.
It compiles only under `-tags e2e_testing` and builds `Control` instances via
Nebula's exported API (the `newSimpleServer` helpers are in Nebula's `_test.go`
files).

A heavier optional capstone is a `nixosTest` running the real systemd units
(`deploy/systemd/`) to cover what the router cannot: an on-disk SIGHUP reload, a
real tun device, and the agent's atomic config rewrite.

Tier 3 drags a heavy external dependency, so it runs only on the scheduled /
manual lane, never on the PR path.

## CI integration (PR-gate vs scheduled)

Fuzzing has no fixed runtime and long simulation/interop runs are slow, so the
suite is split into two CI lanes. **This boundary is normative — keep it pinned
here so it doesn't erode.**

**Fast lane — gates every PR** (the existing `go test -race ./...` + lint):

- all unit/integration tests under `-race`;
- Tier 1 fuzz **seed corpora** and committed crash regressions, run as ordinary
  `go test` (as `FuzzGenerate` does today);
- the **deterministic** Tier 2 invariants (config convergence, token
  single-use, IP-uniqueness, revocation liveness, tenant isolation, cert
  renewal) — seconds to run, reproducible.

**Scheduled / manual lane — never on the PR path** (nightly + `workflow_dispatch`):

- Tier 1 **generative** fuzzing with a bounded `-fuzztime`;
- long / high-fan-out Tier 2 simulation runs;
- Tier 3 Nebula interop (the `e2e_testing` build and the VM test).

Rationale: a slow or flaky gate is one people learn to ignore. Generative
fuzzing cannot gate a PR because its runtime is unbounded; a crasher it finds is
filed and its input committed as a fast-lane regression. The boundary keeps the
PR gate fast and deterministic while the slow, high-yield work runs on a
schedule.

## Diagnosis: making failures legible

The difference between a load test and a diagnostic instrument is whether a
failure names its cause. Three mechanisms:

### Named invariants

The control plane's invariants are defined once, as named checkers run against
the store and the event journal after each scenario step:

- **`IP_UNIQUENESS`** — no two enrolled hosts on a network share any overlay
  address. (Migration 014 normalized addresses into the `host_addresses` table;
  migration 018 added the network-scoped uniqueness constraint that backs this
  at the data layer, and the invariant guards it under concurrency.)
- **`CERT_VALIDATES`** — every issued cert verifies against its issuing CA, and
  against the trust bundle during a rotation overlap.
- **`TENANT_ISOLATION`** — one operator's artifacts never reference another's
  CA; no endpoint leaks another operator's hosts or CAs under any interleaving.
- **`CONFIG_CONVERGENCE`** — after a network change at version V, every live
  host reaches ≥V within bounded polls, exactly once each (no missed rollout,
  no perpetual re-render churn).
- **`REVOCATION_LIVENESS`** — a blocked host's next poll gets 403/410 and the
  loop stops; its fingerprint appears in every peer's blocklist within bounded
  polls.
- **`TOKEN_SINGLE_USE`** — under concurrent redemption, a token yields exactly
  one enrolled host.
- **`CERT_RENEWAL`** — a cert inside its renewal window is auto-renewed on the
  next poll (exercised by advancing the injected clock).
- **`AUDIT_COMPLETE`** — every mutation produces exactly one audit row with the
  correct actor.

A run reports `CONFIG_CONVERGENCE violated`, not `assert failed at line 412`.

### Journal and seeded replay

The driver writes an append-only journal of
`(step, actor, action, target, status, note)`. On a violation the harness emits
a minimal report scoped to the involved entity — the events that touched it and
the last mutation that should have resolved the invariant — so a failure points
at the responsible code path, not just "a host is stuck."

### Scaling smells as numbers, not assertions

A run charts the cost characteristics (blocklist bytes shipped per poll vs fleet
size, per-poll query volume) and logs them rather than asserting on them — e.g.
the "once anything is blocked, every poll ships the full blocklist" behavior is
quantified so a maintainer can decide whether it needs an incremental blocklist.

## Consequences

### Positive

- Closes the gaps unit tests cannot structurally reach: propagation correctness
  at fan-out, tenant isolation under interleaving, cert lifecycle across
  simulated time, enrollment-storm races, and config-injection safety.
- The fuzz targets are cheap on the PR path (seed corpus) and high-yield on the
  schedule (generative), and commit their crashers as regressions.
- Failures are reproducible and self-locating (named invariant + journal).
- The simulation becomes a standing regression harness over hardening fixes —
  protection that a one-off external bug-finder cannot provide.

### Costs

- The clock seam touches `Server` and the signer/renewal paths (additive,
  behavior-preserving when unset).
- Tier 3 depends on a build tag (`e2e_testing`) and Nebula's lower-level
  `Control` construction; the VM capstone adds a `nix`-driven check.
- `internal/simtest/` is new shared test infrastructure to maintain.

### Phasing

1. **Tier 1 — `FuzzGenerate`.** Shipped (#155). It caught the GHSA-7hp6
   round-trip gap on its first run.
2. **Tier 2 — clock seam + `internal/simtest/` + the deterministic invariants.**
   Follows in its own PR, with the clock seam called out for focused review.
3. **CI split.** Add the scheduled lane (generative fuzz; later, long sim and
   Tier 3) alongside the existing fast `-race` gate.
4. **Remaining Tier 1 fuzz targets** (`FuzzValidateIP`, `FuzzEnrollPayload`,
   `FuzzAgentUpdatesHeaders`, `FuzzMigrations`).
5. **Tier 3 — in-process interop via Nebula's `e2e/router`**, then the optional
   VM capstone.

## Related ADRs

- **ADR 0004** — Agent authorization (PoP polls, overlap window) — the protocol
  the virtual agents speak.
- **ADR 0006** — Multi-address overlay — the surface `IP_UNIQUENESS` guards.
- **ADR 0008** — CA rotation — the trust-bundle path `CERT_VALIDATES` checks.

## References

- GHSA-7hp6 / issue #126 — typed-struct config generator.
- #155 — `FuzzGenerate` + the round-trip fix it found (the first Tier 1 piece).
