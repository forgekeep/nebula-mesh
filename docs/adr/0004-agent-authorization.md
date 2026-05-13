# ADR 0004 — Agent authorization model: TTL, proof-of-possession, rotation, revocation

- **Status**: Accepted (2026-05-13); amended (2026-05-13) to introduce a separate Ed25519 signing keypair — see §7.1 and §6.1 row 1.
- **Tracking issue**: [#70](https://github.com/juev/nebula-mesh/issues/70)
- **Implementation issue**: [#75](https://github.com/juev/nebula-mesh/issues/75)
- **Sibling**: [ADR 0003 — CA key encryption model](0003-ca-encryption-model.md) ([#68](https://github.com/juev/nebula-mesh/issues/68))

## 1. Context

The agent-side authorization story today is the thinnest layer of the stack. It works for the happy path (enrol, poll, auto-renew) and quietly mishandles every operational stressor (lost key, compromised host, force-rotate, cert-rotation race, revocation signal). This ADR enumerates the gaps, evaluates three design end-states, studies Tailscale's converged model point-by-point, and records a single decision. Implementation is out of scope and tracked in follow-up issues.

## 2. Current state (as of HEAD)

### 2.1 Enrollment token (`internal/api/hosts.go:103`, `internal/models/token.go`)

- UUIDv4, single-use.
- **TTL hardcoded to 24 hours** — `ExpiresAt: now.Add(24 * time.Hour)`.
- Not configurable per network, per host, or per token.
- `ConsumeToken` atomically rejects not-found / used / expired.

### 2.2 Agent poll authorization (`internal/api/updates.go:25-32`)

- `GET /api/v1/agent/updates?fingerprint=<host-cert-fp>`.
- Server does `store.GetHostByFingerprint(fp)` — **the only authorization check**.
- **No proof-of-possession.** The fingerprint is `SHA-256(cert)`, not a secret. Anyone who observes a single poll request (over plain HTTP, in a log, in a proxy access log, in a packet capture) can replay it from any other host and:
  - pull the current `config.yml` + blocklist,
  - trigger an auto-renew that hands them a freshly signed cert in the response body.
- TLS (when `tls_cert` / `tls_key` are set) is server-auth only. No client certificate is verified.

### 2.3 Auto-rotation (`internal/api/updates.go:63-87`)

- Inside `handleAgentUpdates`, if `pki.ShouldRenew(notBefore, notAfter)`, the server signs a fresh cert (same public key, new expiry) and ships it in the same response.
- `SaveCertificateAndUpdateHostCert` immediately updates `host.cert_fingerprint` in the DB.
- **Race window**: between the DB update and the agent persisting the new cert, the agent's next poll would still use the old fingerprint, which is no longer registered. A network failure or process restart between the response and the disk write leaves the agent locked out (the old fingerprint is gone, the new cert never landed on disk).
- No overlap period during which both fingerprints are accepted.

### 2.4 Revocation

- `BlockHostAndAddToBlocklist` adds the fingerprint to the global blocklist, which is distributed to **other** hosts on their next poll so they refuse to peer with the revoked one.
- The revoked agent itself can keep polling — `handleAgentUpdates` does not consult the blocklist before answering. Whether it gets data depends on whether the host row was also disabled / deleted.
- `DeleteHost` removes the row → subsequent polls return `404`, with no signal the agent can act on.
- There is no `tombstone` status for "blocked but row preserved for audit".

### 2.5 Forced rotation / admin re-issue

- No endpoint to force-rotate a single host's cert outside the `ShouldRenew` window.
- `POST /api/v1/ca/rotate` rotates the CA itself, a strictly larger operation.
- An admin can block / unblock but cannot ask the agent to discard its current key and re-enrol with a new keypair.

### 2.6 Recovery from key loss

- If `host.key` is wiped (disk failure, reinstall), the only path is `DELETE` + new host record + fresh enrollment token. Audit history, IP allocation, group membership all churn.
- No re-enrollment endpoint for an existing host record.

## 3. Forces

- **F1. Self-hosted, single-binary deployment story.** Anything we choose must work behind any proxy that forwards plain HTTP, must require no external TLS terminator unless the operator opts in, and must not bloat the agent or server binary beyond what fits "on a $5 VM".
- **F2. Unattended signing is a feature.** Auto-rotation must keep working without operator presence. This rules out schemes that require interactive operator approval per poll.
- **F3. Backwards compatibility window.** Old agents in the field will not speak the new auth. A graceful migration matters more than a single-shot rip-and-replace.
- **F4. The agent already owns a long-lived keypair** (`host.key` + `host.crt` from enrollment). We do not need to invent a second identity; we need to start using the one we already issue.
- **F5. Plain HTTP must keep working** for users who terminate TLS at a proxy or who run on a trusted LAN. The auth design cannot rely on `crypto/tls.ClientAuth` being available end-to-end.
- **F6. Observability.** Today's silent `404` on unknown fingerprint hides the most interesting class of attacker behaviour (replay, scanning). Every failed auth must produce an audit entry.

## 4. Design questions

The ADR must give an answer for each:

1. **Token policy.** Configurable TTL per network / per token? Regeneratable without deleting the host?
2. **Proof-of-possession on poll.** What does the agent present, and what does the server verify?
3. **Cert rotation overlap.** Accept both old and new fingerprints for a grace window?
4. **Revocation signal to the revoked agent.** Structured `403 revoked` (with reason / timestamp / message)? Behaviour on `404`?
5. **Forced rotation endpoint.** Shape; same key or new keypair?
6. **Re-enrollment for an existing host.** Mint a new token bound to the row?
7. **Replay protection.** Nonce / timestamp window?
8. **Interaction with rate limiting.** Bypass on auth success, or keep as defence in depth?
9. **Backwards compatibility.** Server-side accept-mode flag (`legacy | signature | mtls | strict`)?
10. **Telemetry / audit.** What does every failed auth attempt look like in the audit log?

## 5. Options to compare

### 5.1 Option A — Minimal

Stay on fingerprint-only auth; fix the cert-rotation race and add audit entries for failed auth attempts.

Concretely:

- Token TTL stays at 24 h.
- Add an `accept-set` column or in-memory map of `(host_id, prev_fingerprint, expires_at)` populated whenever auto-renew happens. The server accepts polls with either fingerprint until the old one expires (e.g. one poll interval after the new cert lands).
- Add a `host.auth.failed` audit entry per unknown-fingerprint poll, with masked IP + user-agent.
- Force-rotate, re-enroll, revocation signal — **not added**. Continue to require host delete + new token for recovery.

**Threat model.**

| Attacker has… | Outcome under Option A |
|---|---|
| One captured poll request (URL with `fingerprint=…`) | replay succeeds — same as today |
| `host.crt` without `host.key` | replay succeeds — same as today |
| `host.crt` + `host.key` | full impersonation — same as today |
| DB read | full impersonation — same as today |
| CA compromise | full mesh compromise — same as today |

**Cost.** Small. One migration to track previous fingerprint, one audit-event family, no protocol change.

### 5.2 Option B — HTTP-signed poll requests

Use `host.key` to sign every poll request. Signature plus fingerprint goes in headers; server verifies the signature against the public key inside `host.crt` and checks the blocklist + host status.

Sketch:

```
GET /api/v1/agent/updates HTTP/1.1
Host: mgmt.example.com
X-Nebula-Fingerprint: <sha256-of-host.crt>
X-Nebula-Timestamp:   2026-05-13T08:30:00Z
X-Nebula-Nonce:       <16 random bytes, base64>
X-Nebula-Signature:   <Ed25519 / X25519-derived signature over the
                       canonical string:
                         METHOD || PATH || HOST || TIMESTAMP || NONCE>
```

Verification is `O(1)` after the row lookup. Replay protection comes from a `±N minutes` timestamp window plus a small server-side LRU of recently seen nonces. Plain HTTP works (the signature is independent of transport).

Also includes everything from Option A (rotation overlap + audit entries) plus:

- **Configurable token TTL.** `enrollment_token.ttl: "1h" | "24h"` per network, default 24 h; tokens regeneratable through `POST /api/v1/hosts/{id}/enrollment-token`.
- **Force-rotate endpoint.** `POST /api/v1/hosts/{id}/rotate-cert?new_key=true|false`. Flag in the next poll response asks the agent to discard its current key and re-enrol with a new keypair, using a server-minted single-use token returned in the response.
- **Re-enroll endpoint.** `POST /api/v1/hosts/{id}/reenroll` mints a fresh single-use token bound to the existing host row (preserves IP, groups, audit history).
- **Revocation signal.** Server returns `403 revoked` with body `{reason, timestamp, message}` when the host is in `blocked` state instead of silently accepting. Agent logs loudly and stops; with `--token` re-supplied at restart, can re-enrol if a fresh token is pre-provisioned.
- **Audit entry on every failed auth** as in Option A.

**Threat model.**

| Attacker has… | Outcome under Option B |
|---|---|
| One captured poll request | replay fails — signature is bound to timestamp+nonce; expired within minutes |
| `host.crt` without `host.key` | replay fails — cannot forge signatures |
| `host.crt` + `host.key` | full impersonation — unchanged, intrinsic to any PoP scheme |
| DB read | impersonation requires `host.key` too, which is not in the DB |
| CA compromise | full mesh compromise — orthogonal to poll auth |

**Cost.** Medium. New crypto helper on agent (sign), new verification helper on server (verify), one migration for the `last_nonce_seen` LRU (or in-memory), spec a stable canonical request string. Reverse proxies are unaffected — the signature lives in normal HTTP headers.

### 5.3 Option C — Mutual TLS

Listener-level client-cert verification for `/api/v1/agent/*`. Server requires the agent to present `host.crt` as a TLS client certificate; the TLS handshake itself is the proof of possession.

Includes everything from Option B (force-rotate, re-enroll, rotation overlap, structured revocation, audit) plus:

- Per-route mTLS — separate listener for `/api/v1/agent/*` or reverse-proxy header forwarding (`X-SSL-Client-*`).
- Configuration story: in-binary TLS requires the operator's cert chain visible to nebula-mgmt; reverse-proxy story requires the proxy to verify and forward verified-client-cert headers.

**Threat model.**

Same end-state as Option B against captured-request / captured-cert / captured-key attackers; arguably stronger by virtue of not putting verification logic in our codebase (TLS stack handles it). The cost is deployment surface.

**Cost.** High. Two listeners or a proxy-config requirement. Operators on plain HTTP setups are blocked. The reverse-proxy story for client-cert forwarding is bespoke per proxy. Plays badly with F1 / F5.

## 6. Prior art — Tailscale's converged model

[Tailscale](https://tailscale.com/) solves a comparable problem at scale (long-lived agent identity + coordination plane + revocation + rotation + admin device delete) and the design has been published in their security pages and engineering blog. The point of comparing is **not to copy** — our deployment model differs (self-hosted single binary vs SaaS coordination plane, Nebula vs WireGuard, certificate-mesh vs key-only). The point is to make each adopt / adapt / reject decision **explicit**, rather than rediscovering each mechanism in isolation.

### 6.1 Mechanism-by-mechanism table

| Tailscale mechanism | What it does | Maps to | Decision |
|---|---|---|---|
| **Node key as durable identity** — each device generates a public/private keypair at first auth; the public key is registered with the coordination server and is the device's permanent identity. | Long-lived per-device asymmetric key, decoupled from the cert it might present elsewhere. | We have it: `host.key` + `host.crt` from enrollment. The cert's public key is the durable identity. | **Adopt with one adjustment.** `host.key` (X25519) remains the Nebula handshake key; the cert is its certified form. **Additionally**, the agent generates an Ed25519 signing keypair (`host.signing.key` / `host.signing_pub`) at enrollment and registers `signing_pub_pem` with the server. This second key exists purely because X25519 is a key-agreement scheme and cannot sign arbitrary messages (see §7.1). Both keys share lifetime — the rotation / force-rotate / re-enroll flows rotate them together. |
| **Noise protocol on the control channel** — every coordination call is encrypted and authenticated under the node key; PoP is built into the transport. | Coordination plane is end-to-end-encrypted and authenticated independently of TLS. | Option B is the lightweight analogue: HTTP-signed requests rather than a full Noise handshake. | **Adapt.** We do not need a Noise channel — HTTP signatures over plain HTTP (or HTTPS-terminated-anywhere) match our F1 / F5 forces. The point we adopt is "PoP must be on every coordination call, not just enrollment". |
| **Pre-auth keys** — pre-issued enrollment tokens with configurable TTL, single-use **or** reusable, ephemeral (auto-deletes the node at expiry) or persistent, taggable for non-interactive workloads. | Flexible enrollment-token policy beyond our hardcoded 24 h single-use. | §2.1 + §5.2's "configurable token TTL" answers (1) from §4. | **Adapt.** Make TTL configurable per network with a 24 h default. Single-use stays the default; reusable / ephemeral / tag-bound keys deferred until there is a demand signal (we have neither autoscale fleets nor IaC patterns yet). |
| **Key expiry / forced re-auth** — default 180-day node-key expiry per tailnet, configurable per device, "no expiry" for servers; on expiry the node is forced through re-auth (interactive, or via pre-auth key for headless). | Periodic identity re-issuance separate from cert renewal. | Our 30-day cert renewal is **cert** rotation, not **identity** rotation — the keypair never changes. | **Adapt (partial).** Add `POST /hosts/{id}/rotate-cert?new_key=true` so an admin can force the agent through a fresh keypair when warranted (compromise, scheduled re-key). Do **not** add a built-in 180-day expiry by default — that breaks unattended mesh ops in a way Tailscale tolerates because they have a UI plumbed everywhere; we do not. |
| **Tailnet lock** — cryptographic multi-party approval for adding nodes; the coordination server alone cannot enrol a node, existing signing nodes must co-sign. | Strong-tenant security feature for high-trust networks. | Not in scope today. | **Reject for now, mention as deferred.** Multi-party signing requires UX we do not have (per-operator signing keys distinct from the API key) and customer demand we have not seen. Tracked as a future ADR if it materialises. |
| **Device delete / disable signal** — admin removes a node, the coordination connection returns an explicit, structured signal (not a silent 404), so the agent logs loudly and stops. | Matches §4.4 directly. | Today: silent 404 on deleted host; silent OK on blocked host. | **Adopt.** `403 revoked` (blocked) and `410 gone` (deleted). Agent logs at WARN/ERROR, exits its retry loop, optionally re-enrols if a token is pre-provisioned via `--token` at restart. |
| **OIDC / SSO binding** — user identity attaches to a node at first auth, survives node-key rotation. | Trace operator → host through identity rotation. | We already have `host.owner_operator_id` via the per-operator CA / network owner chain. | **Adopt (already done).** No change needed; mention in the ADR that the binding survives `rotate-cert?new_key=true` because the host row is preserved. |

### 6.2 What we explicitly do *not* import from Tailscale

- **Noise on the wire.** Their threat model assumes the coordination plane crosses the public internet between unknown intermediaries. We can rely on either HTTPS (terminated wherever) plus HTTP signatures, or the operator's existing reverse-proxy TLS story. Adding a Noise handshake inside our HTTP would duplicate that protection.
- **DERP / relay servers.** Our control plane does not need to relay agent-to-agent traffic — that is Nebula's job, separate from this ADR.
- **MagicDNS / 100.64.0.0/10 IP assignment.** Address allocation lives in our existing networks / host create flow; orthogonal.
- **Default 180-day node-key expiry.** See §6.1 row 4 — incompatible with our unattended-mesh promise unless we add operator UX we do not have.

## 7. Decision

**Adopt Option B (HTTP-signed poll requests + token policy + force-rotate + re-enroll + structured revocation + audit) with the Tailscale-derived adaptations from §6.**

The deciding factors:

1. Option A leaves the impersonation risk on the table (§2.2). Captured-request replay is a realistic attacker in any deployment that runs plain HTTP behind a corporate proxy or terminates TLS at the load balancer. We do not want to ship that posture.
2. Option C (mTLS) is the strongest answer but is incompatible with F1 / F5 — too many operators run nebula-mesh on plain HTTP behind their own proxies, and the "client-cert forwarding header" story is bespoke per proxy.
3. Option B works **anywhere HTTP works** (the signature is in headers, transport-independent), keeps the binary single, and matches Tailscale's "PoP on every coordination call" principle without their full Noise stack.
4. The token / rotation / revocation / re-enrol additions in Option B answer the operational stressors the issue enumerates without forcing every operator through a TLS-termination decision.
5. Cert-rotation race (§2.3) gets the same overlap-window fix in any option; including it in B keeps it bundled with the auth rework rather than as a drive-by patch.

### 7.1 Specifics

- **Token TTL.** Configurable per network (`enrollment_token.ttl`, default 24 h). Per-token override at create time. `POST /api/v1/hosts/{id}/enrollment-token` regenerates the token without churning the row.
- **Poll PoP.** `X-Nebula-Fingerprint` + `X-Nebula-Timestamp` + `X-Nebula-Nonce` + `X-Nebula-Signature`. Signature over `METHOD || "\n" || PATH || "\n" || HOST_HEADER || "\n" || TIMESTAMP || "\n" || NONCE`. **Algorithm: Ed25519.** A dedicated signing keypair (`host.signing.key` / `host.signing_pub`) is generated by the agent during enrollment and registered with the server alongside `public_key_pem`. The server verifies via `crypto/ed25519.Verify(signing_pub, canonical, signature)`. Rationale: `host.crt`'s public key is X25519 (Curve25519 DH for the Nebula handshake) and cannot sign arbitrary messages; `slackhq/nebula/cert` does not expose a general `Sign(privKey, msg)` API. The signing key reuses `crypto/ed25519` from the standard library, no new dependency. The fingerprint header still identifies the host's cert; the signature is verified against the bound signing public key. Time skew tolerated: ±5 minutes. Nonce LRU: in-process bounded map per `(host_id, nonce)`, size cap 65 536, eviction on size or 10-minute idle; we accept missing the rare cross-restart replay because the timestamp window already bounds the attack to 5 minutes per restart.
- **Cert rotation overlap.** New column `hosts.prev_cert_fingerprint` populated on auto-renew, cleared at the next successful poll under the new fingerprint **or** after wall-clock 2× poll interval (whichever first). Server accepts polls under either value while populated.
- **Revocation signal.** `403 revoked` on blocked hosts with body `{reason, blocked_at, message}`. `410 gone` on deleted hosts. Agent stops the poll loop, logs at ERROR, exits 0 (systemd will not auto-restart on `0`); operator runs `nebula-agent` again with a fresh `--token` if pre-provisioned, otherwise the legacy "delete + new host" path.
- **Force-rotate.** `POST /api/v1/hosts/{id}/rotate-cert?new_key=true|false`. Same-key rotation re-signs immediately; new-key rotation sets a `pending_rekey` flag on the host row; next poll response carries `{rekey_required: true, enrollment_token: <new>}`; agent generates **both** a fresh X25519 keypair (for the cert) and a fresh Ed25519 signing keypair, calls `/api/v1/enroll` with both public keys, swaps all key/cert files atomically, resumes polling.
- **Re-enroll.** `POST /api/v1/hosts/{id}/reenroll` mints a fresh single-use token bound to the existing row. Audit entry `host.reenroll.requested`.
- **Replay protection.** Timestamp window + nonce LRU (above). Documented clock-skew expectation: NTP synced to within 60 s.
- **Rate-limit interaction.** Keep the `agent_poll` bucket as defence-in-depth. Successful auth does **not** bypass the bucket; we already issue 60/120 which is generous for the typical 30 s poll interval.
- **Backwards compatibility.** Server-side `agent_auth: legacy | signature | strict` flag in `server.yml`. `legacy` accepts unsigned polls (today's behaviour), `signature` accepts both unsigned and signed (warns on unsigned via audit entry), `strict` rejects unsigned with `400 missing_signature`. Default flips `legacy → signature` in the same release the agent learns to sign; flips `signature → strict` two releases later. Agents bumped in parallel so users who upgrade both at once never see a regression.
- **Audit telemetry.** New entries: `host.auth.failed` (with reason: `unknown_fingerprint | bad_signature | timestamp_skew | replayed_nonce | revoked | gone`), `host.auth.legacy_accepted` (signature mode only, for migration visibility), `host.rotate-cert.requested`, `host.reenroll.requested`.

### 7.2 Out of scope for the follow-up implementation

- Tailnet-lock-style multi-party signing for new hosts.
- 180-day mandatory identity re-auth.
- mTLS at the listener level (revisited once a clear customer asks).
- Pre-auth keys with `reusable: true` / `ephemeral: true` / tag-bound semantics.
- Hardware-token-bound host keys.
- Agent-side key rotation without server cooperation.

These remain backlog candidates; none of them is blocked by the chosen design.

## 8. Migration story

- **Release N.** Implement signature verification on the server (`agent_auth: legacy` default, accepts both); ship the new audit entries; add the overlap window column and the structured revocation responses. No agent change yet.
- **Release N+1.** Bump the agent to sign all polls. Server default flips to `agent_auth: signature` (accepts both, warns on legacy). README + `docs/agent.md` updated to recommend `strict` once the fleet is migrated. Force-rotate / re-enroll endpoints + UI controls land here.
- **Release N+2.** Server default flips to `agent_auth: strict`; legacy unsigned polls return `400`. Operators with un-bumped agents must upgrade. Release notes call this out one release in advance.

Operators stuck on N agents during N+2 server can downgrade the flag to `signature` while they finish the agent rollout — the flag is not removed, just no longer the default.

## 9. Consequences

- A follow-up implementation issue tracks the work; this ADR is a precondition.
- `internal/api/updates.go`, `internal/api/hosts.go`, `internal/api/enroll.go`, `internal/agent/poller.go`, `internal/agent/enroll.go`, `internal/store` and one new migration touched. No CA-side changes (orthogonal to ADR 0002 / 0003).
- Agents store a second key on disk: `host.signing.key` (mode 0600) alongside `host.key`. The server stores `signing_pub_pem` in a new column on the `hosts` row. Both keys are rotated together by the force-rotate and re-enroll flows.
- README + `docs/agent.md` add "Agent authorization" sections explaining the headers, signing key, and rotation/revocation signals.
- Failed-auth audit entries will require a UI surface — the existing `/ui/audit-log` page should render them with their reason codes.
- Backups: unchanged. The new column is just one more host-row field.

## 10. Acceptance criteria for this ADR

- [x] `docs/adr/0004-agent-authorization.md` exists, status: **Accepted**.
- [x] Each gap from §4 has a documented decision in §7.
- [x] Options A / B / C are sketched with threat models and operational costs.
- [x] Tailscale's model is summarised and §6.1 maps each mechanism (node key, Noise, pre-auth keys, key expiry, tailnet lock, device delete signal, OIDC binding) to **adopt / adapt / reject** with reasoning.
- [x] A preferred option (B) is chosen with reasoning (§7).
- [x] Backwards-compatibility / migration story is explicit (§8).
- [x] Implementation is **out of scope** — tracked in a follow-up issue once the ADR is accepted.

## 11. References

- Issue: <https://github.com/juev/nebula-mesh/issues/70>
- [ADR 0002 — Per-operator CAs](0002-per-operator-cas.md)
- [ADR 0003 — CA key encryption model](0003-ca-encryption-model.md)
- `internal/api/enroll.go` — current enrollment handler
- `internal/api/updates.go` — current poll handler, auto-renew logic, rotation race
- `internal/api/hosts.go:99-103` — hardcoded 24 h token TTL
- `internal/models/token.go` — enrollment token model
- `internal/agent/poller.go` — agent-side poll loop
- Tailscale: <https://tailscale.com/security>, <https://tailscale.com/blog/how-tailscale-works>, <https://tailscale.com/kb/1085/auth-keys>, <https://tailscale.com/kb/1226/tailnet-lock>
