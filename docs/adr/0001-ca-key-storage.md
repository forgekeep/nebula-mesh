# ADR 0001 — CA key storage: file-system vs database

- **Status**: Superseded by [ADR 0007](0007-remove-legacy-ca-stack.md) (2026-05-15)
- **Decision**: keep CA private key material in encrypted files outside the SQLite database.
- **Context**: issue [#11](https://github.com/juev/nebula-mesh/issues/11) — *Evaluate storing CA key material in the database*.

## 1. Background — current model

`nebula-mgmt init` generates the Nebula CA and writes two files into the configured `data_dir`:

| Path | Contents | Permissions |
|---|---|---|
| `ca.crt` | X.509 public certificate (PEM). Embedded in every Nebula config. | `0644` |
| `ca.key` | PKCS#8 private key encrypted with the operator-supplied passphrase. | `0600` |

The passphrase is **not** persisted; it is supplied on every `nebula-mgmt serve` via:

1. the `NEBULA_MGMT_CA_PASSPHRASE` environment variable (recommended for systemd / Docker);
2. an interactive TTY prompt when the env var is unset (recommended for manual operation).

The SQLite database (`db_path`) holds operational state: networks, hosts, certificates, blocklist, audit log, operators. It contains no key material that would let an attacker mint Nebula certificates.

## 2. Forces

- **A. Operations**: backing up two artifacts (DB + `data_dir`) is slightly more complex than backing up one file.
- **B. Migrations**: container / VM image rebuilds must remember to mount or copy both `data_dir` and the DB.
- **C. Threat model**: an attacker with read access to the SQLite file currently cannot sign or revoke certificates. Adding the (encrypted) CA key into the same file would concentrate sensitive material.
- **D. Disaster recovery**: a corrupted DB does not invalidate the CA; the operator can rebuild operational state from the agents' certificates and the unchanged `ca.crt` / `ca.key`.
- **E. Familiarity**: file-based key storage with passphrase encryption is the well-trodden path for offline CAs (step-ca, smallstep, Vault PKI's file backend, OpenSSL CA, …).
- **F. Code simplicity**: the current `pki.CAManager` reads from disk in `init`/`serve` and has no DB dependency. Moving to DB-backed storage requires plumbing through the store interface, migrations, online passphrase change flows, and rollback behavior.

## 3. Options considered

### Option A — Status quo: encrypted file under `data_dir`

- (+) Smallest blast radius: DB compromise alone cannot mint certificates.
- (+) Compatible with hardware tokens / external KMS in a future iteration by swapping `pki.CAManager`.
- (+) Mature tooling: file permissions, OS keychains, `chattr +i`, etc.
- (+) Backups are obvious: `tar` over `data_dir`.
- (−) Operators must remember to back up two trees (`data_dir` + DB).
- (−) Slightly noisier for container deployments (two volumes).

### Option B — Encrypted CA key blob in SQLite

- (+) One backup target.
- (+) Slightly simpler container layouts (single volume).
- (−) Concentrates risk: anyone with read access to `nebula.db` now needs only the passphrase to mint certificates.
- (−) DB-level operations (e.g. `sqlite3` shells, `pragma` calls, accidental `SELECT *`) can leak the encrypted blob; file-level controls (chmod, group ownership, AppArmor profiles) no longer apply to the key path independently.
- (−) Adds non-trivial migration code: read existing `ca.key`, decrypt, re-encrypt with new operational password (or reuse), insert into DB, validate end-to-end, then delete the file. Each step must be reversible.
- (−) Passphrase rotation becomes more complex — must re-encrypt the in-DB blob without leaving plaintext at rest.
- (−) Disaster recovery: a corrupted SQLite file now loses *both* operational state *and* the CA key.

### Option C — External secret manager (Vault Transit / KMS / HSM)

- (+) Best security posture: signing happens inside the KMS; the server never holds the private key.
- (−) Out of scope for a self-hosted, single-binary deployment story.
- (−) Significant operational dependency (Vault / KMS uptime, IAM, audit).
- *Deferred.* See "Future work" below.

## 4. Decision

**Accept Option A. Keep the CA private key in `data_dir/ca.key` (PKCS#8, passphrase-encrypted).**

Rationale:

- The current model already meets the deployment shapes the project ships today (systemd, Docker, manual install). The mild operational cost of a second backup target does not justify trading away the threat-model separation provided by file-level controls.
- DB-backed storage delivers convenience without changing the worst-case outcome (attacker with passphrase plus key material → can mint certificates). It merely shifts where the attacker reads the encrypted blob from.
- The project is too young to commit to an irreversible storage migration for security-critical material. Should requirements change, the `pki.CAManager` interface is the only seam that needs to change, so this decision is cheap to revisit.

## 5. Concrete consequences

- No schema migration is needed for issue [#11](https://github.com/juev/nebula-mesh/issues/11).
- `nebula-mgmt init` continues to write `ca.crt` and `ca.key` into `data_dir`.
- `nebula-mgmt serve` continues to require `NEBULA_MGMT_CA_PASSPHRASE` (or interactive prompt).
- Operator documentation must clearly call out **two** things to back up: `data_dir` and `db_path`. Updated in `README.md` together with this ADR.
- We will not accept future PRs that move CA key material into the DB unless this ADR is superseded by a follow-up ADR with new evidence (e.g. a deployment scenario that the file model cannot serve).

## 6. Backup & restore guidance

Run as the user owning `data_dir`:

    sudo tar --xattrs -czf /backups/nebula-mgmt-$(date +%F).tar.gz \
        /var/lib/nebula-mgmt/ca.crt \
        /var/lib/nebula-mgmt/ca.key \
        /var/lib/nebula-mgmt/nebula.db

Restoring is the inverse: stop the service, extract over `data_dir`, restart, supply the passphrase. The CA passphrase must be obtained from your secret manager — it is intentionally not in the backup.

## 7. Future work (out of scope for this ADR)

- **External KMS / HSM signing path**. If/when requested, add a `pki.Signer` interface and an alternate implementation that delegates signing to Vault Transit / cloud KMS / PKCS#11. No DB storage needed; the server holds only a handle, not key material.
- **CA rotation tooling**. Already partially supported by `POST /api/v1/ca/rotate`; document operator-facing recovery and key-ceremony procedures.
- **At-rest disk encryption guidance** (LUKS / cloud volume encryption) as defence-in-depth for the file-based CA key.

## 8. References

- Issue: <https://github.com/juev/nebula-mesh/issues/11>
- Current code: `internal/pki/ca.go`, `internal/cli/init.go`, `internal/cli/serve.go`
- Nebula docs on CA generation: <https://nebula.defined.net/docs/guides/quick-start/>
