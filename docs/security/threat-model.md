# Threat model

STRIDE threat model for nebula-mesh (`nebula-mgmt` control plane + `nebula-agent`).
It records the assets at stake, the entry points and trust boundaries, the
attacks considered per boundary, the mitigations in place (with code / ADR /
issue references), and the residual risks that are accepted by design.

This document is a living baseline: when an entry point, asset, or mitigation
changes, update the relevant section so the "verified safe" conclusions stay
reproducible rather than living only in issue comments (#178).

Reporting process and supported versions: see [SECURITY.md](../../SECURITY.md).

## 1. System overview

```
            untrusted internet
                   │
        ┌──────────┴───────────┐
        │   nebula-mgmt        │   control plane (HIGH VALUE)
        │  ┌────────────────┐  │   - signs Nebula certificates
        │  │ API  /api/v1   │  │   - holds CA private keys + master KEK
        │  │ Web  /ui       │  │   - holds operator creds + enroll tokens
        │  │ PKI / keystore │  │
        │  │ store (SQLite) │  │   data at rest: enc. CA keys, hashes
        │  └────────────────┘  │
        └──────────┬───────────┘
       enroll/poll │ (TLS)
        ┌──────────┴───────────┐
        │   nebula-agent       │   on each host: enroll, poll, write files
        └──────────┬───────────┘
                   │
            slackhq/nebula        overlay data plane (OUT OF SCOPE — upstream)
```

Trust zones, from least to most trusted:

| Zone | Principal | Authenticates with |
|------|-----------|--------------------|
| Public | anonymous | none (`/healthz`, `/readyz`, optionally `/metrics`) |
| Agent | an enrolled host | single-use enroll token, then Ed25519 proof-of-possession |
| Operator (non-admin) | an operator session / API key | bcrypt login (+ TOTP), or bearer API key; scoped to **owned** CAs |
| Operator (admin) | an admin operator | same, plus the `admin` role gate |
| Host/operator | the deployer | env (`NEBULA_MGMT_MASTER_KEY`), CLI, config file |

## 2. Assets

| ID | Asset | Protection at rest / in transit | References |
|----|-------|--------------------------------|------------|
| A1 | CA private keys | Envelope encryption: per-CA DEK (AES-256-GCM) wrapped under the master KEK; never written in plaintext. Zeroized on the error path and after decode. | ADR 0001, ADR 0003; `internal/keystore`; #181, #196 |
| A2 | Master KEK (`NEBULA_MGMT_MASTER_KEY`) | Supplied via env only; never logged, never in argv. Decoded buffer zeroized after building the AEAD. | ADR 0003; #196 |
| A3 | Operator credentials & sessions | Passwords bcrypt-hashed; API keys hashed at rest; sessions are random tokens; cookie `HttpOnly` + `SameSite=Lax` + `Secure`-gated. | `internal/web/session.go`; #180 |
| A4 | Enrollment tokens | `crypto/rand` UUID, SHA-256 at rest, single-use via an atomic conditional consume; bound to a specific `host_id`. | ADR 0004; #197 |
| A5 | Certificate-signing authority | Every sign path is gated by `checkIssuanceAllowed` (blocked host / disabled operator → refuse). | GHSA-339v-266x-79xr; `internal/revocation` |
| A6 | Network topology & host metadata | Reads scoped to the caller's owned CAs/networks; revocation blocklist scoped per-CA. | #154, #203 |

## 3. Entry points & trust boundaries

| ID | Entry point | Boundary crossed | AuthN | AuthZ |
|----|-------------|------------------|-------|-------|
| E1 | Management API `/api/v1/*` | public → operator | bearer API key | `canAccessHost/Network/CA`; admin gate on operator/settings/blocklist/audit |
| E2 | Web UI `/ui/*` | public → operator | session cookie + CSRF | session role + ownership checks; `requireAdmin` group |
| E3 | Agent enroll `POST /api/v1/enroll` | public → agent | single-use enroll token | token bound to `host_id`; issuance guard |
| E4 | Agent poll `GET /api/v1/agent/updates` | agent → control plane | Ed25519 proof-of-possession | identity = matched cert fingerprint; per-CA data scope |
| E5 | OIDC login | public → operator | IdP (OIDC code flow) | state + single-use code; JIT role defaults to `user` |
| E6 | CLI / config / env | host operator → process | local OS trust | n/a (deployer is trusted) |
| E7 | Unauthenticated probes `/healthz` `/readyz` `/metrics` | public | none / optional bearer | redacted output; `/metrics` opt-in auth |

## 4. STRIDE per entry point

### E1 — Management API
- **Spoofing**: API key required; keys hashed at rest, revocable; disabled operators rejected (re-check on every request, #147).
- **Tampering**: write actions ownership-checked; input bounded (host name/groups #186, firewall selectors #195).
- **Repudiation**: mutating actions write an audit-log entry; audit-log read is admin-gated.
- **Information disclosure**: list/read scoped to owned CAs in SQL (#154); blocklist scoped per-CA (#203); no cross-tenant IDOR (403 not 404 side-channel documented & accepted).
- **DoS**: request body capped + HTTP timeouts (#185); per-IP rate limit (#52). Authenticated legitimate-use DoS is out of scope (SECURITY.md).
- **Elevation**: no general "update operator" sink → no `role` mass-assignment (Netmaker CVE-2026-29195 class refuted); admin-only operator/settings endpoints.

### E2 — Web UI
- **Spoofing / Tampering**: CSRF double-submit token on every `/ui` mutation; constant-time login (#180); TOTP step non-skippable.
- **Information disclosure**: SSE `/ui/events` authenticated and scoped to owned networks, fail-closed.
- **Elevation**: `requireAdmin` gates operator/settings management.
- **Session**: rotated on privilege transition; invalidated on logout, operator-disable, and password reset (#204).

### E3 — Agent enroll
- **Spoofing / Replay**: token is single-use (atomic consume, #197), TTL-bounded, and bound to a `host_id` server-side — a token cannot enroll a different host.
- **Elevation**: certificate fields (`Name`, `NebulaIPs`, `Groups`) come from the DB host row, not the request body.
- **Issuance abuse**: blocked host / disabled operator refused before signing (GHSA-339v-266x-79xr).

### E4 — Agent poll
- **Spoofing**: identity is the certificate fingerprint; the Ed25519 PoP signature is verified against *that host's* `signing_pub_pem`. Host A cannot poll as host B without B's signing key.
- **Replay**: per-host nonce + ±5 min timestamp window.
- **Information disclosure**: peer config and blocklist scoped to the polling host's own CA/network (#203).
- **Revocation**: blocked → `403`; deleted → `410`; rotation overlap bounded by `prev_cert_fingerprint` / `cert_rotated_at`.

### E5 — OIDC
- **Spoofing / CSRF**: `state` parameter (single-use, TTL), authorization-code single-use, ID-token verified.
- **Elevation**: JIT-provisioned operators default to role `user`, never `admin`; email-verification enforced.
- **Open redirect**: post-login redirect hardcoded to `/ui/`.

### E6 — CLI / config / env
- The deployer is trusted. Hardening: master key env-only; SSRF guards on `alerts.webhook_url` / `oidc.issuer` (#188); TLS required unless loopback or explicit `--insecure-http` (#179).

### E7 — Unauthenticated probes
- `/readyz` redacts DB error text (#187); `/debug/vars` and `/metrics` are bearer-gated / opt-in auth (#187).

## 5. Cross-cutting mitigations

- **Transport**: TLS by default; non-loopback plaintext bind refused unless opted in (#179).
- **Crypto**: AES-256-GCM throughout; GCM tag binds AAD/nonce (envelope attacks refuted); key material zeroized (#181, #196).
- **Input**: strict JSON decode, body caps, length bounds on cert-embedded fields (#186, #195).
- **Tooling baseline**: `golangci-lint` (pinned), standalone `gosec`, and `govulncheck` gate every PR, plus ADR-0009 generative fuzzing in CI.

## 6. Residual risks & accepted trade-offs

| Risk | Why accepted | Compensating control |
|------|--------------|----------------------|
| A compromised `nebula-mgmt` can mint a certificate for any host | Inherent to a control plane that holds the CA (headscale/Tailnet-Lock class) | Protect the control plane: TLS, durable revocation, least-privilege deploy |
| Authenticated legitimate-use DoS | Explicitly out of scope (SECURITY.md) | Rate limits + body caps reduce blast radius |
| Pre-fix orphan blocklist rows (host already deleted, no `ca_id`) are broadcast to all CAs | Cannot recover the CA for an orphan; never weaken revocation | Fail-safe broadcast only; all new revocations are CA-scoped (#203) |
| TOCTOU between admin re-check and a mutating SQL statement | Window is small and the action still requires a valid admin session | `isActiveAdmin` re-reads role from DB per request (#147) |
| Plaintext / no-TLS deployments | Out of scope when not following the README | TLS-by-default + loopback-only insecure bind (#179) |
| Upstream `slackhq/nebula` data-plane issues | Out of scope — report upstream | n/a |

## 7. References

- ADRs: 0001 (CA key storage), 0002 (per-operator CAs), 0003 (CA encryption), 0004 (agent authorization), 0008 (CA rotation), 0009 (scale & fuzz testing).
- Advisory: GHSA-339v-266x-79xr (host revocation not durable) — fixed in v0.3.7.
- Hardening issues: #179, #180, #181, #185, #186, #187, #188, #195, #196, #197, #203, #204.
- Follow-ups: #208 (offensive test bench), #209 (tooling baseline).
- Audit history & methodology: #178.
