# Backup and restore

The control plane keeps everything a mesh cannot afford to lose in one SQLite
database: CA metadata and **encrypted** CA private keys, operators, API keys,
enrollment tokens, the audit trail, and all network/host state. `nebula-mgmt
ops backup` and `nebula-mgmt ops restore` make a consistent snapshot of that
database a first-class, scriptable operation instead of a hand-rolled
`sqlite3 .backup`.

## What a backup contains — and what it does not

A backup is a single gzipped tar archive holding:

- a `manifest.json` (archive format version, binary version, schema version, timestamp), and
- a `nebula.db` snapshot taken with SQLite's `VACUUM INTO`, which is consistent under WAL.

It deliberately does **not** contain:

- **The master key** (`NEBULA_MGMT_MASTER_KEY`). CA private keys in the snapshot
  are encrypted under it; without the key the archive is inert. Store and rotate
  the master key separately — a backup plus the master key is what restores a
  mesh, and keeping them apart is what lets you ship archives to less-trusted
  storage.
- **`server.yml`.** Treat the server config as configuration-as-code (version
  control, your config-management tool), not backup payload.

## Taking a backup

```sh
nebula-mgmt ops backup --config /etc/nebula-mgmt/server.yml --output /backups/nebula-$(date +%F).tar.gz
```

`--output` must not already exist (the command refuses to overwrite a backup).

For archives leaving trusted storage, encrypt with a passphrase
(AES-256-GCM, scrypt KDF):

```sh
nebula-mgmt ops backup --config /etc/nebula-mgmt/server.yml \
  --output /backups/nebula-$(date +%F).tar.gz.enc --passphrase "$BACKUP_PASSPHRASE"
```

Backups are safe to take while the server is running.

### Cadence

Back up after any change to CAs, operators, or networks, and on a schedule
(e.g. a daily cron or systemd timer) sized to how much host/enrollment churn you
can afford to replay. Keep the master key and the archives in separate trust
domains.

## Restoring

Restore into a host whose `server.yml` points at the data dir you want to
populate, with the **same** `NEBULA_MGMT_MASTER_KEY` the backup was taken under:

```sh
export NEBULA_MGMT_MASTER_KEY=...   # the original key
nebula-mgmt ops restore --config /etc/nebula-mgmt/server.yml --input /backups/nebula-2026-06-13.tar.gz
```

Restore guards against the common foot-guns:

- It **refuses to overwrite an existing database**. Pass `--force` to replace
  one; the current database is moved to `<db_path>.pre-restore` (and stale
  `-wal`/`-shm` files are cleared) before the snapshot is written.
- It **runs migrations forward** when the backup's schema is older than the
  binary, so an old archive restores cleanly onto a newer release.
- It **verifies the master key can decrypt every restored CA** and fails loudly
  if it cannot — you find out at restore time, not at the first certificate
  signing. A mismatched key leaves the restored database in place but exits
  non-zero with a clear message.

For an encrypted archive, pass the same `--passphrase` used to create it.

## Restore drill

Practice the restore before you need it:

1. On a throwaway host, point `server.yml` at an empty data dir.
2. `export NEBULA_MGMT_MASTER_KEY=...` with the production key.
3. `nebula-mgmt ops restore --config … --input <latest backup>`.
4. Confirm the "verified N CA key(s) decrypt under the master key" line and that
   `nebula-mgmt ca list` / `nebula-mgmt host list` show the expected state.

A backup you have never restored is a hypothesis, not a backup.

## Migrating to a new server

1. Take a backup on the old server.
2. Install `nebula-mgmt` on the new server and write its `server.yml`.
3. Copy the archive and set `NEBULA_MGMT_MASTER_KEY` to the original key.
4. `nebula-mgmt ops restore --config … --input …`.
5. Start the server and verify agents continue to poll and rotate.

## Mesh import recovery

Take a backup immediately before creating or finalizing an existing-mesh import
session. The SQLite snapshot includes the imported encrypted CA, session token
hash and expiry, collected sanitized snapshots, temporary hosts, revision and
finalized topology. The raw `nmi_` token and every host private key are absent;
keep neither in the backup archive.

If collection fails before finalize, cancel the session. Remote Nebula files
have not changed, so no database restore is needed. A retry uses a new session
and new token; do not reuse a canceled session's token.

If managed configuration breaks connectivity after finalize:

1. Stop `nebula-agent` on affected hosts so it cannot reapply the same version.
2. Restore `<nebula_config_path>.pre-nebula-mesh.<import_session_id>` atomically
   as the active Nebula config and reload Nebula. Keep the existing CA,
   certificate and private key files.
3. Correct the topology in the control plane. If the entire finalized import
   must be undone, stop `nebula-mgmt` and restore the pre-finalize archive with
   the matching `NEBULA_MGMT_MASTER_KEY`.
4. Verify the restored CA/Network/Host inventory before restarting agents.

Restoring only the database does not roll back files already applied on hosts.
Restoring only host configs does not roll back the server's finalized state;
coordinate both sides when reverting the whole adoption.
