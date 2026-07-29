# ADR 0010 — Keyed credential verifiers

- **Status**: Accepted
- **Date**: 2026-07-29
- **Context**: Issue [#338](https://github.com/forgekeep/nebula-mesh/issues/338) — replace persisted unkeyed credential verifiers.

## Context

Operator API keys, Web sessions, enrollment tokens, mesh-import tokens, and
TOTP recovery codes are bearer credentials. A database-only compromise must not
provide an accept-ready verifier for those values. Passwords remain a separate
case: they use bcrypt because users choose their entropy.

The deployment already requires `NEBULA_MGMT_MASTER_KEY` to decrypt CA
material. Adding a separate credential secret would create a second mandatory
backup and restore dependency. Reusing the master directly would blur its
cryptographic roles.

## Decision

Derive a credential-verifier root from `NEBULA_MGMT_MASTER_KEY` with HKDF-SHA-256
and the stable label `nebula-mesh/credential-hash/root/v1`. Use that root only
for HMAC-SHA-256 credential verifiers. Each supported purpose is encoded in the
MAC input, so the same plaintext has different digests for operator API keys,
sessions, enrollment tokens, mesh-import tokens, and TOTP recovery codes.

Persist a versioned digest (`hmac-sha256-v1:<lowercase-hex>`). The prefix makes
the format explicit and lets a later migration introduce a new controlled
version.

The verifier root is coupled to the master key. Changing the master key makes
existing HMAC credentials unusable, in addition to its existing effect on CA
material. Master-key rotation, CA rewrapping, and credential reissue are a
separate future operation.

Use a clean cutover. Legacy SHA-256 digests cannot be transformed into an HMAC
without the plaintext, so migration 027 revokes or deletes them atomically and
does not provide a legacy lookup, dual-read path, or downgrade compatibility.

## Consequences

- Existing sessions, API keys, recovery codes, and pending tokens are
  invalidated. Password hashes, OIDC binding, TOTP secrets, and enrolled-agent
  certificate authentication remain valid.
- The upgrade requires a stopped server. Rolling and mixed-version operation
  are unsupported because an old process can only write legacy digests.
- Restoring an old backup with a new binary is restore-forward: it applies the
  cutover again. Rollback requires the old binary plus a pre-upgrade database
  backup and the matching master key.
- A database dump without the master key cannot compute a verifier accepted by
  the server. A compromise of both the database and matching master key remains
  equivalent to control-plane compromise.

## Rejected alternatives

- **Legacy fallback or lazy rehash.** It retains an unkeyed production lookup
  path and leaves downgrade behavior dependent on individual credential use.
- **A separate credential secret.** It improves operational key separation but
  adds another mandatory deployment and restore secret without removing the
  existing master-key dependency.
- **bcrypt or Argon2 for random bearer tokens.** These values have high entropy;
  expensive verification on unauthenticated paths adds avoidable
  resource-exhaustion exposure.
