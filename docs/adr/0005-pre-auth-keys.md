# ADR 0005 — Pre-auth keys: reusable, ephemeral, tag-bound enrollment tokens

- **Status**: Accepted, **implementation deferred** until a trigger materialises (see §10). The design is recorded now so it does not have to be invented under pressure when the trigger arrives.
- **Tracking issue**: [#76](https://github.com/forgekeep/nebula-mesh/issues/76)
- **Depends on**: [ADR 0004 — Agent authorization model](0004-agent-authorization.md) — configurable token TTL + the `enrollment_tokens` schema this ADR extends.
- **Sibling**: [ADR 0002 — Per-operator CAs](0002-per-operator-cas.md) — token ownership is scoped to the operator who minted it.

## 1. Context

[ADR 0004 §7.2](0004-agent-authorization.md) explicitly defers "pre-auth keys with `reusable: true` / `ephemeral: true` / tag-bound semantics" pending a demand signal. This ADR makes the deferral explicit and writes the design down so we don't reinvent it later.

Today's enrollment token (after the ADR 0004 implementation: configurable TTL, still single-use) works for hand-enrolling a handful of long-lived hosts. It does not fit:

- A Terraform module that spins up N nodes from one image — needs N distinct tokens minted out-of-band.
- A nightly CI job that boots a runner, enrols, runs a build, tears down — needs the host row to auto-disappear, not accumulate as a tombstone.
- A Kubernetes DaemonSet on a cluster that adds / removes nodes — needs a token that survives many redemptions and a host lifecycle that ties to node lifecycle.
- A fleet of edge devices owned by group X — needs every host enrolled under that group/tag without per-host operator action.

Tailscale solved this with **pre-auth keys** (also called *auth keys*). The point of this ADR is to make the per-mechanism decision explicit so the implementation, when it lands, doesn't drift.

## 2. Current state (as of HEAD, post-ADR 0004)

### 2.1 `enrollment_tokens` schema (`internal/models/token.go`, ADR 0004 §7.1)

- `id`, `host_id`, `token`, `expires_at`, `created_at`.
- TTL configurable per network via `enrollment_token.ttl`; default 24 h.
- Single-use: `ConsumeToken` atomically rejects not-found / used / expired.
- Bound to a specific host row at create time (`host_id` is `NOT NULL`).
- Regeneratable via `POST /api/v1/hosts/{id}/enrollment-token` without churning the host row.

### 2.2 Enrollment flow (`internal/api/enroll.go`)

- `POST /api/v1/enroll` consumes a token, signs the cert, registers the public keys, returns cert + CA + config. Token row marked used.
- The flow has no concept of "create the host row on first redemption" — the host always exists in `pending` state before the agent shows up.

### 2.3 Audit (`internal/api/audit.go`)

- `host.enroll.completed` audit entry stamps the operator who created the host (transitively, through the token → host → operator chain). Token id is not currently part of the entry.

## 3. Design questions

The ADR must give an answer for each. Mirrors the research-question list in the tracking issue.

1. **Reusable tokens.** N redemptions? Cap at create time or open-ended until manual revoke / TTL expiry? Concurrent-redemption race story?
2. **Ephemeral hosts.** Auto-delete when the cert expires? Interaction with the ADR 0004 overlap window? Default cert lifetime? Audit footprint after the row vanishes?
3. **Tag / group binding.** Tokens that auto-add their hosts to one or more groups? Multi-group? Mutability of the binding post-enroll?
4. **Token lifecycle.** Max TTL? Revocation endpoint? List endpoint?
5. **Security implications.** Leaked reusable token blast radius? Leaked ephemeral + reusable? Tag-bound token leak (group-equivalent credential)?
6. **UX.** API + CLI ergonomics for the three common shapes (fleet, CI, k8s).
7. **Migration from ADR 0004.** Additive schema changes? Backwards compatibility shim required?

## 4. Options to compare

### 4.1 Option A — Single-use only (status quo after ADR 0004)

Defer all of this. Operators script around it: one `POST /hosts` + one `POST /enrollment-token` per node, then ship the token out-of-band.

**Threat model.**

| Attacker has… | Outcome under Option A |
|---|---|
| One enrollment token | enrols **one** node, against the host row the operator pre-created; further redemptions fail (`token used`). |
| The operator's API key | unbounded — same posture as today, orthogonal to this ADR. |
| Leaked token + leaked group-bind script | unchanged — group binding is operator-applied, not token-applied. |

**Cost.** Zero. Operators feel the toil; we collect demand-signal data.

**When this wins.** As long as no operator asks for fleet provisioning, the toil cost is paid by hypothetical future users, not present ones. Optionality is real.

### 4.2 Option B — Reusable + ephemeral + tag-bound (full Tailscale shape)

Make `enrollment_tokens` carry:

```
ALTER TABLE enrollment_tokens
  ADD COLUMN max_uses        INTEGER NOT NULL DEFAULT 1,    -- 1 = single-use, 0 = unbounded
  ADD COLUMN uses_remaining  INTEGER NOT NULL DEFAULT 1,    -- atomic decrement on redeem
  ADD COLUMN ephemeral       INTEGER NOT NULL DEFAULT 0,    -- 1 → host auto-deletes on cert expiry
  ADD COLUMN group_bindings  TEXT    NOT NULL DEFAULT '[]', -- JSON array of group names
  ADD COLUMN created_by      TEXT    NOT NULL DEFAULT '',   -- operator id (per-operator scope)
  ADD COLUMN revoked_at      TIMESTAMP;                     -- soft-revoke, blocks future redemptions
```

And switch `host_id` from `NOT NULL` to `NULLABLE` — a multi-use token is not bound to a single host. On redemption, when `host_id IS NULL`, the server creates the host row inside the same transaction that decrements `uses_remaining`.

Endpoints:

- `POST /api/v1/enrollment-tokens` — mint. Body: `{network_id, max_uses?, ephemeral?, group_bindings?, ttl?}`. Defaults: `max_uses=1, ephemeral=false, group_bindings=[], ttl=24h`.
- `GET /api/v1/enrollment-tokens` — list for the calling operator (admin sees all).
- `DELETE /api/v1/enrollment-tokens/{id}` — soft-revoke (sets `revoked_at`); in-flight enrols already past `consumeToken` are unaffected.
- `POST /api/v1/enroll` — unchanged shape; the server figures out single-use vs multi-use from the row.

Adds everything from Option A plus:

- **Reusable.** Atomic `UPDATE enrollment_tokens SET uses_remaining = uses_remaining - 1 WHERE token = ? AND uses_remaining > 0 AND (max_uses = 0 OR uses_remaining <= max_uses) AND revoked_at IS NULL AND expires_at > NOW() RETURNING id, network_id, …`. SQLite supports `RETURNING` since 3.35 — already in our minimum.
- **Ephemeral.** A daily sweeper (`go.background.ephemeral_sweep`) deletes ephemeral host rows whose cert `notAfter < NOW()`. Cert-expiry timestamp lives on the host row already. The sweep is idempotent and lock-free.
- **Tag binding.** On redemption, the server adds the host to every group in `group_bindings` inside the redeem-transaction. Groups must exist at token-create time (validated then, not at redeem time — fail closed if a group was deleted between create and redeem).
- **Per-operator scope.** Tokens are owned by the operator who minted them (`created_by`). The list endpoint filters by `created_by`; admin sees all. The redeem flow does not consult ownership — once the token is in someone's hands they can spend it (intentional; that's the point of a pre-auth key).

**Threat model.**

| Attacker has… | Outcome under Option B |
|---|---|
| One leaked reusable token | enrols `uses_remaining` arbitrary nodes under the bound groups until detection / revoke / TTL expiry. Mitigations: shorter TTL by default for reusable (capped at 7 d), per-token rate limiting on redeem, `enrollment_token.redeems` audit entries surfaced in `/ui/audit-log` so spikes are visible. |
| One leaked single-use token (existing posture) | unchanged — single redemption. |
| One leaked ephemeral + reusable token | low per-host blast radius (cert dies in 24 h) but high churn — attacker can keep redeeming until detection. Audit visibility is the only real defence. |
| Leaked tag-bound token | hosts land in the bound groups automatically — group-equivalent credential. Operator must treat the token list page as a sensitive credential list (we surface this in the UI). |
| Server compromise | unbounded — orthogonal to this ADR. |

**Cost.** Medium. One migration (the `ALTER TABLE` above + a backfill of `created_by` from existing audit entries, single `UPDATE`). New endpoints. New `/ui/enrollment-tokens` page. New ephemeral-sweep goroutine. Token shape is additive — every existing token gets `max_uses=1, ephemeral=false, group_bindings=[], created_by=<inferred>` and behaves identically.

### 4.3 Option C — Reusable only, no ephemeral, no tags

Half of Option B: `max_uses` + `uses_remaining` only. Operators get fleet provisioning (one token for N nodes) but the host rows accumulate and the group toil remains.

**Threat model.** Same as B's reusable row. The leaked-tag-bound row goes away (no tags), but the leaked-ephemeral row also goes away (no auto-delete safety), so the trade is wash-ish.

**Cost.** Small migration (one new column, one new column). One new endpoint + UI. No sweeper. But ephemeral hosts are exactly the case k8s / CI care about most, so this leaves the most-requested shape on the table.

**When this wins.** If the demand signal is "long-lived edge fleet" (Terraform / Ansible) and not "short-lived workers" (k8s / CI). Rare in practice — even Terraform-managed fleets churn on machine replacement.

### 4.4 Option D — External-identity-bound tokens

Token redemption requires the caller to also present an OIDC token / cloud-provider IMDS attestation / GitHub-Actions OIDC token. A leaked enrollment token alone is insufficient.

**Threat model.** Strongest, by a wide margin. A leaked token is harmless without an attestable identity to pair it with.

**Cost.** High. We need a per-network "trusted issuer" config, JWT validation, JWKS rotation, audience pinning, and a per-issuer mapping rule from JWT claims to `host.name` / `host.groups`. Operators on a single-binary on-prem deployment without an OIDC provider are blocked. The UX is bespoke per cloud.

**When this wins.** If our customer is a large multi-tenant SaaS where the enrollment token is treated as a bearer credential and external identity is already plumbed. Not our population today; nice future option.

## 5. Prior art — Tailscale + Headscale

[Tailscale's auth keys](https://tailscale.com/kb/1085/auth-keys) and [Headscale's open-source implementation](https://github.com/juanfont/headscale) of the same primitives are the design reference. The point of comparing is *not to copy* — our deployment model differs — but to make each adopt / adapt / reject decision explicit.

### 5.1 Mechanism-by-mechanism table

| Tailscale / Headscale mechanism | What it does | Decision |
|---|---|---|
| **Reusable auth keys** — a single key spends N redemptions until `max_uses` is hit or the TTL fires. | Fleet provisioning without minting per-host tokens. | **Adopt.** §4.2's `max_uses` + `uses_remaining`. |
| **Ephemeral auth keys** — hosts minted from the key auto-disappear when the cert expires. | k8s / CI / autoscale lifecycle without tombstone rows. | **Adopt.** §4.2's `ephemeral` flag + background sweep. |
| **Tagged auth keys** — keys are bound to one or more `tag:foo` ACL tags; redeemed hosts inherit the tags. | Non-interactive workloads with predefined ACL scope. | **Adopt, scoped to our groups.** `group_bindings` instead of "tags"; semantics identical (auto-add to N groups). |
| **Pre-approved keys** — the key carries pre-approval, so the host skips the manual "approve this device" step in the admin UI. | Headless / non-interactive enrollment. | **Already our default.** Our enrollment flow does not have a separate approve step — a redeemed token directly enrols. No change needed. |
| **Server keys** — auth keys whose hosts never have to re-auth (no 180-day node-key expiry). | Long-lived servers in a tailnet with mandatory expiry. | **Reject.** ADR 0004 §6.1 already rejected mandatory 180-day expiry; we have no analogue. |
| **Tailnet-lock co-signing for new hosts** — multi-party approval before a fresh key can enrol. | High-trust multi-admin tenants. | **Reject (deferred).** Same reasoning as ADR 0004 §6.1 — requires per-operator signing keys we do not have yet. Tracked separately. |
| **Admin UI: token list / revoke / create** — every active key is listed with `{id, type, max_uses, uses_remaining, expires_at, tags}`. | Operator visibility into outstanding credentials. | **Adopt.** New `/ui/enrollment-tokens` page mirroring `/ui/cas`. |
| **`tailscale up --authkey=…`** — agent reads the key from a flag or env var. | Ergonomic enrollment from automation. | **Already done.** Our agent supports `--token` since the first release; the same flag accepts a pre-auth key without a code change. |

### 5.2 What we explicitly do *not* import

- **180-day mandatory re-auth.** ADR 0004 §6.1 already vetoed this; mentioned again because it shows up in Tailscale's auth-key UX (`expiry: never` is an explicit checkbox there).
- **Default-reusable on the create form.** Tailscale's UI defaults to single-use; we keep that default. Multi-use is opt-in.
- **`pre_authorized` / `pre_approved` checkbox.** Our flow does not have an approve step; the flag would be a no-op.
- **Cloud-provider attestation binding.** This is Option D; reserved as a future ADR if the demand signal points that way.

## 6. Decision

**Adopt Option B (reusable + ephemeral + tag-bound), but defer implementation until a trigger arrives (§10).**

The deciding factors:

1. Option A leaves the per-host toil on the table; the moment one customer asks for fleet provisioning, A becomes the wrong answer fast. Option C is a half-step that solves only the fleet case and not the CI / k8s case — that's the more common ask in practice (workers churn faster than long-lived servers).
2. Option D is the strongest threat model but locks out our single-binary on-prem population. Reserved for a future ADR if the customer base shifts.
3. Option B's threat-model worst case (leaked reusable + tag-bound token) is *bounded* by TTL, by `uses_remaining`, by per-token revoke, and by audit visibility. The UI must treat the token-list page as a sensitive credential list (the way `/ui/cas` already is); operators who treat it that way pay no marginal risk.
4. The schema delta is additive (§4.2) — every existing token keeps working under the inferred defaults. No migration shim.
5. Tailscale's primitives are mature and well-understood; we're not blazing a trail.

### 6.1 Specifics

- **Token defaults.** `max_uses = 1, ephemeral = false, group_bindings = [], ttl = network's `enrollment_token.ttl` (default 24 h)`. Reusable tokens are capped at TTL ≤ 7 d (server-enforced); operators who need longer must mint a fresh one.
- **Atomic redemption.** `UPDATE … RETURNING` (see §4.2). Two concurrent agents redeeming the last use of a token: one wins, the other gets `409 token_exhausted`. No `SELECT … FOR UPDATE` needed — SQLite serialises writes via WAL.
- **Ephemeral sweep.** Single goroutine in `cmd/nebula-mgmt`, runs every 30 minutes. Deletes host rows where `ephemeral = 1 AND cert_expires_at < NOW() - 1h`. The 1 h buffer keeps a host alive long enough to gracefully shut down with the existing rotation overlap window. Sweeper logs at INFO `ephemeral hosts swept: <count>`.
- **Audit shape.** New entries: `enrollment_token.created`, `enrollment_token.redeemed` (with `{token_id, host_id, uses_remaining_after}`), `enrollment_token.revoked`, `enrollment_token.exhausted` (auto-emit when `uses_remaining` hits 0), `host.ephemeral.swept`. Foreign-key on `audit.host_id` survives an ephemeral host's deletion (`LEFT JOIN` everywhere; nullable acceptable).
- **API surface.**
  - `POST /api/v1/enrollment-tokens` → `{token, id, max_uses, expires_at, group_bindings, ephemeral}`.
  - `GET /api/v1/enrollment-tokens` → list scoped to caller (admin sees all).
  - `DELETE /api/v1/enrollment-tokens/{id}` → soft-revoke. Returns `204`.
  - `POST /api/v1/enroll` — unchanged shape; server handles the multi-use path internally.
- **UI surface.** `/ui/enrollment-tokens` lists the calling operator's tokens; `/ui/enrollment-tokens/new` is the mint form (network, max_uses, ephemeral, group_bindings, TTL). Mirrors `/ui/cas` ownership / admin-sees-all behaviour. The list page badges `reusable` / `ephemeral` / `revoked` so a leaked credential is obvious at a glance.
- **CLI ergonomics.** No agent flag changes; `nebula-agent --token <pre-auth>` already works for single-use and will work for multi-use without a code change (the agent does not need to know token shape — the server decides).
- **Rate limit.** New token-redeem bucket: 20/min per `(token_id, source_ip)`. Prevents a leaked reusable token from being drained instantly.

### 6.2 Out of scope for the eventual follow-up implementation

- External-identity binding (Option D). Future ADR if the customer base shifts.
- Tailnet-lock-style co-signing for token creation. Future ADR if multi-admin trust becomes a real ask.
- Hardware-token-bound signing keys for the resulting hosts. Orthogonal to token shape; tracked separately if it surfaces.

These remain backlog candidates; none is blocked by this design.

## 7. Migration story

The migration is **additive and forward-only**. No legacy shim is needed.

- **Release N** (when the trigger from §10 lands). Implement the schema delta (`ALTER TABLE enrollment_tokens` from §4.2). Existing tokens auto-fill defaults; they continue to behave as before. Ship `POST /api/v1/enrollment-tokens` + the list/revoke endpoints + the `/ui/enrollment-tokens` page. Audit entries added. Default sweep interval 30 minutes.
- **Release N+1.** No follow-up required — there is no agent-side change. If demand warrants, add CLI helpers (`nebula-mgmt token mint --reusable --ephemeral --group=runners`) for ergonomics; not blocking.

There is no `agent_auth: legacy | strict` analogue for tokens — token *redemption* shape did not change; only token *creation* gained options. Old agents (single-use mental model) keep enrolling under `max_uses=1` exactly as they did pre-N.

## 8. Consequences

- A follow-up implementation issue tracks the actual work; this ADR is its precondition.
- Files touched by the eventual implementation: `internal/store/migrations/`, `internal/store/sqlite_tokens.go`, `internal/api/enroll.go`, `internal/api/hosts.go` (token mint helpers), one new `internal/api/enrollment_tokens.go`, `internal/web/enrollment_tokens.go` + templates, `cmd/nebula-mgmt` (sweeper). No agent-side changes.
- DB grows by five columns on `enrollment_tokens`; one nullable on `host_id`. SQLite handles this with `ALTER TABLE … ADD COLUMN` (no rewrite).
- README + `docs/agent.md` add an "Enrollment tokens" section once the implementation lands. The `--token` flag docs do not change.
- The new `/ui/enrollment-tokens` page becomes a sensitive credential list; operator-permission audit-log review responsibility includes it.

## 9. Acceptance criteria for this ADR

- [x] `docs/adr/0005-pre-auth-keys.md` exists, status: **Accepted, implementation deferred**.
- [x] Each research question from §3 has a documented decision in §4 / §6.
- [x] Options A / B / C / D are sketched with threat models and operational costs.
- [x] Tailscale's auth-key mechanism is summarised in §5 with per-knob adopt / adapt / reject decisions, and Headscale called out as the open-source implementation reference.
- [x] A preferred option (B) is chosen with reasoning (§6).
- [x] Migration / additive schema story is explicit (§7).
- [x] Implementation is **out of scope** — tracked in a future follow-up issue once the trigger from §10 materialises.

## 10. Triggers — when to open the implementation issue

This ADR is **not urgent**. Open the implementation issue when one of these surfaces:

- A user requests fleet provisioning (Terraform / Ansible / k8s) for nebula-mesh and the per-host enrollment toil is the stated friction.
- A CI runner enrollment use case becomes real (someone files an issue, opens a discussion, or contributes a proof-of-concept).
- Per-host enrollment toil shows up as a stated complaint in any operator-feedback channel.
- ADR 0004's implementation has fully landed and shipped for one release, and we want to layer the fleet story on top while the auth code is fresh.

Until then this ADR is a parked decision: when the trigger fires, the design is already done; we go straight to implementation.

## 11. References

- Tracking issue: <https://github.com/forgekeep/nebula-mesh/issues/76>
- [ADR 0002 — Per-operator CAs](0002-per-operator-cas.md)
- [ADR 0004 — Agent authorization model](0004-agent-authorization.md) — §7.2 lists this work as deferred
- ADR 0004 implementation issue: [#75](https://github.com/forgekeep/nebula-mesh/issues/75)
- Tailscale auth keys: <https://tailscale.com/kb/1085/auth-keys>
- Tailscale tags + ACL: <https://tailscale.com/kb/1068/tags>
- Headscale (open-source coordination server): <https://github.com/juanfont/headscale>
- `internal/api/enroll.go` — current enrollment handler the redemption path extends
- `internal/models/token.go` — current `EnrollmentToken` shape (single-use, TTL only)
