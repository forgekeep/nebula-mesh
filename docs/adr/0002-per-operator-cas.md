# ADR 0002 — Per-operator CAs with encrypted in-DB key storage

- **Status**: Implemented (extended by [ADR 0007](0007-remove-legacy-ca-stack.md), 2026-05-15)
- **Supersedes**: [ADR 0001](0001-ca-key-storage.md) (CA key storage: file-system vs database)
- **Tracking issue**: [#31](https://github.com/juev/nebula-mesh/issues/31)

## 1. Context

ADR 0001 (Accepted 2026-05-12) committed nebula-mesh to a single, server-wide CA stored as an encrypted PKCS#8 file under `data_dir/`. That decision was correct under the assumptions in place at the time: one operator account, one trust domain per server, simple OS-level controls on a single file.

Since then, multi-operator support has landed (PR #22), together with TOTP, OIDC, per-operator API keys, audit log with actor, self-registration, and admin-only operator management. Operators can already create multiple **networks** on the same server, but every network is signed by the same single CA. There is no real cryptographic isolation: any compromise of a host certificate in any network is — at the Nebula trust layer — usable to impersonate inside any other network on the same control plane.

This ADR records the decision to **introduce per-operator CAs and move CA private key material into SQLite, encrypted at rest**, superseding ADR 0001. It is the design step the issue requires before implementation.

## 2. Forces

- **A. Tenant isolation.** A self-hosted control plane is attractive for small teams that share infrastructure but not trust (family, club, hobby cluster, friends-of-friends). With one shared CA, "I run my mesh on your server" is not a defensible promise.
- **B. Independent lifecycles.** Operators want to rotate, rebuild, or destroy their CA without coordinating with everyone else on the box.
- **C. ADR 0001's blast-radius argument revisited.** ADR 0001 §3B argued that keeping the encrypted CA key outside SQLite limits the damage from a DB-only compromise: an attacker who reads only `nebula.db` cannot mint certificates. That argument held while there was **one** key and **one** decryption passphrase managed out-of-band. With N per-operator CAs, the out-of-band channel becomes N independent secrets — N passphrases in N env vars, or one master key plus N derived keys. The file-system approach loses its main advantage (a single, ergonomic out-of-band secret) and gains operational pain (N files with bespoke permission schemes per operator, password-rotation ceremonies per CA, fragile backup of N artifacts).
- **D. Operational ergonomics.** A `cas` SQL table is far easier to enumerate (`SELECT id, name, owner FROM cas`) than N opaque files. Atomic transactions across the rest of the schema become trivial.
- **E. Backup surface.** ADR 0001 §6 already required backing up *two* trees (`data_dir` + `db_path`). Moving CA material into the DB collapses the on-disk backup target to one file. The master key / per-CA passphrases stay in the operator's secret manager — they are still **not** in the backup.
- **F. Future external KMS (ADR 0001 §7).** The `pki.Signer` seam contemplated for KMS/HSM signing is independent of where the *current* in-DB blob lives. A future ADR can swap the in-DB `cas.encrypted_key_material` for a KMS handle without touching the rest of the schema.

## 3. Options considered

### A. Status quo: one file-system CA per server (ADR 0001)

- (+) Smallest code change today.
- (−) Does not meet issue #31's primary goal — no tenant isolation.
- (−) "Add per-operator CAs while keeping them on disk" expands to N files with bespoke ACLs and N passphrases held out-of-band; the original ergonomic argument inverts.

### B. N file-system CAs (one encrypted file per CA in `data_dir/cas/<id>.{crt,key}`)

- (+) Preserves the threat-model wording of ADR 0001 verbatim for each individual CA.
- (−) Filesystem ownership / permission policy per CA becomes a custom operational story (UID-per-operator? per-CA group? AppArmor profiles?).
- (−) N independent passphrases must be supplied to `nebula-mgmt serve` somehow at startup — env vars, secret-manager wrappers, an unlock prompt per CA. None of these scale.
- (−) Atomic "create CA + link to operator + record audit entry" across a file and the DB is fragile (no two-phase commit).

### C. Encrypted in SQLite, envelope encryption with a server master key — **chosen**

- (+) Single backup target (`db_path`); master key lives in the operator's secret manager and is **never** written to disk or to the DB.
- (+) Atomic schema operations: `INSERT INTO cas (…) ; INSERT INTO audit_log (…)` in one transaction.
- (+) Operator-facing UX: one env var (`NEBULA_MGMT_MASTER_KEY`), N CAs underneath it.
- (+) Path to future KMS: replace the local AEAD with a `pki.Signer` against KMS, keep the schema.
- (−) DB compromise + master-key compromise = full breach. **Acceptable** because (a) the master key is short and stored exactly where the operator already stores other production secrets, (b) ADR 0001's "DB alone" attacker is a strictly weaker threat than the one that motivates the work, (c) we still ship the master key out-of-band so the DB by itself remains useless.
- (−) Re-encrypting all CAs is required to rotate the master key (ergonomically: a `nebula-mgmt master-key rotate` ceremony). Documented; deemed acceptable.

### D. KMS / HSM at signing time (deferred, ADR 0001 §7)

- (+) Best long-term posture; private key never on the host.
- (−) Out of scope for the self-hosted, single-binary deployment story we ship.
- *Deferred.* The chosen design must not block this. We achieve that by isolating signing behind a `pki.Signer` interface so the in-DB implementation can be swapped without schema churn.

## 4. Decision

Adopt Option C: **per-operator CAs, encrypted at rest in SQLite, using envelope encryption with a server master key.**

Concretely:

- A new `cas` table holds, per CA:
  - `id` (UUID), `name`, `owner_operator_id`, `cert_pem`, `fingerprint`, `not_before`, `not_after`, `status` ('active'|'retired'), `created_at`, `updated_at`,
  - `encrypted_key_dek` — the **data-encryption key** (DEK) for this CA, wrapped under the master key,
  - `encrypted_key_material` — the CA's PKCS#8 private key, encrypted under the DEK (AES-256-GCM),
  - `nonce_dek` and `nonce_key` — distinct 12-byte nonces.
- `networks`, `hosts`, `certificates`, and `blocklist` gain a non-null `ca_id` foreign key.
- The server master key is supplied at start-up via `NEBULA_MGMT_MASTER_KEY` (raw 32 random bytes, base64-encoded) or read from a file referenced by `master_key_file` in `server.yml`. It is **never** written to the database nor to any auto-generated log line.
- Existing `NEBULA_MGMT_CA_PASSPHRASE` is repurposed: at the first start after migration, if a legacy `data_dir/ca.key` is present, the server prompts/reads the old passphrase, decrypts the legacy key, re-wraps it under a fresh per-CA DEK derived from the master key, inserts the row into `cas` with `name='default'`, `owner=<seeded admin>`, and stops reading the file on the next start. The file remains on disk for one release as a manual rollback artifact.

### 4.1 Key handling

- DEKs are generated with `crypto/rand` per CA at creation and never leave memory unwrapped.
- The wrapping algorithm is AES-256-GCM; keys / nonces are zeroised in the buffer after use.
- The decrypted PKCS#8 blob lives only inside the signing closure; the helper returns the signed certificate, not the key.
- Loading a CA at signing time always re-reads the row, decrypts, signs, zeroises. There is no long-lived in-process cache of unwrapped keys.

### 4.2 Ownership and authorization

- A CA is owned by **exactly one operator** (`owner_operator_id`). The seeded admin owns the migrated "default" CA.
- A non-admin operator can:
  - create their own CAs;
  - sign, list, rotate, retire, delete their own CAs;
  - create networks under their own CAs only;
  - never operate on CAs they do not own.
- An admin can manage any CA. Audit log entries record both the actor and the CA id.

### 4.3 Schema changes

| Table | Change |
|---|---|
| `cas` (new) | `(id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, created_at, updated_at)` |
| `networks` | + `ca_id TEXT NOT NULL REFERENCES cas(id) ON DELETE RESTRICT`. Default-CA id stamped on existing rows during migration. |
| `hosts` | + `ca_id TEXT NOT NULL REFERENCES cas(id)` (denormalised for fast enrollment lookups; matches the host's network's ca_id at insert time). |
| `certificates` | + `ca_id TEXT NOT NULL REFERENCES cas(id)`. |
| `blocklist` | + `ca_id TEXT NOT NULL REFERENCES cas(id)`. |

### 4.4 Threat model revision

We accept that **(DB read) + (master-key read)** is now equivalent to having all CA private keys. ADR 0001's stronger claim — "DB alone is useless" — is **preserved**, because the master key is supplied at startup from outside the DB and is not auto-persisted. The two assets must be compromised together for an attacker to mint certificates. Operationally this is the same posture as ADR 0001 (which required both `ca.key` and the passphrase together), with the added benefits of single-target backups, atomic schema mutations, and N-tenant isolation.

What we **lose** vs ADR 0001:

- An attacker with shell access to the SQLite file *and* the env var of a running server gets all CAs at once, not one. We weight this against the tenancy benefit and ADR 0001 §3B's premise that the single CA was already a single point of failure.
- File-level ACLs (chown, chmod, AppArmor) no longer protect the key path independently from the DB path. The DB file inherits `0640 root:nebula-mgmt` by default.

These regressions are documented in the README under "Backups & key handling" together with the chosen master-key delivery mechanism.

### 4.5 Migration

The very first `nebula-mgmt serve` after upgrading runs migration `009_cas` and follows this sequence (all in one transaction except where noted):

1. `CREATE TABLE cas (…)`.
2. `ALTER TABLE networks/hosts/certificates/blocklist ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';` (SQLite cannot add a non-default NOT NULL column; we add it with a sentinel and tighten in step 6).
3. If `data_dir/ca.crt` and `data_dir/ca.key` exist and the `cas` table is empty, prompt the operator for `NEBULA_MGMT_CA_PASSPHRASE` (or read from env), decrypt the legacy key, generate a fresh DEK, wrap under the master key, and `INSERT` a row with `name='default'`, `owner_operator_id=<seeded admin's id>`, `status='active'`.
4. `UPDATE networks  SET ca_id = (SELECT id FROM cas WHERE name='default') WHERE ca_id = '';`
5. Same for `hosts`, `certificates`, `blocklist`.
6. SQLite `ALTER TABLE` does not enforce `REFERENCES` retroactively; we rely on application-layer constraint checks (`ca_id != ''`) until a future migration rewrites the tables.
7. Commit. The legacy `data_dir/ca.{crt,key}` files are left untouched for one release for manual rollback.

Rollback: keep running the previous server version; the new columns are unused, the new table is ignored.

### 4.6 Out of scope

- Cross-CA trust / chaining (each CA is a separate trust domain by definition).
- Sharing a single host across CAs.
- KMS / HSM signing (still deferred, see §3D).

## 5. Consequences

- Implementation work follows in a separate PR; this ADR is a precondition for it per issue #31.
- ADR 0001 is **superseded**. The "Decision" section of ADR 0001 should be read alongside the link to this document.
- Operators on existing installs must set `NEBULA_MGMT_MASTER_KEY` before upgrading; the upgrade fails fast if the variable is unset and the database contains any data.
- Backup documentation collapses to "back up `db_path`; keep `NEBULA_MGMT_MASTER_KEY` in your secret manager". The `data_dir/ca.{crt,key}` files are still backed up for one release as a rollback artifact, then deletable.

## 6. Acceptance criteria for this ADR

- [x] ADR 0002 exists and is marked **Accepted** with today's date.
- [x] ADR 0002 supersedes ADR 0001 explicitly.
- [x] The encryption scheme is named (AES-256-GCM envelope encryption with a server master key).
- [x] The threat model from ADR 0001 §2C / §3B is revisited and the new posture is documented.
- [x] Ownership model, schema changes, migration strategy, key handling, and out-of-scope items are documented.

Implementation acceptance from issue #31 (in-DB encrypted storage, schema migration, authorization, audit, docs) is delivered by the follow-up implementation PR.

## 7. References

- Issue: <https://github.com/juev/nebula-mesh/issues/31>
- ADR 0001: [docs/adr/0001-ca-key-storage.md](0001-ca-key-storage.md)
- Multi-operator work: PR #22 (`feat(auth): support multiple operator users (foundation)`)
- Current single-CA code: `internal/pki/ca.go`, `internal/cli/init.go`, `internal/cli/serve.go`
