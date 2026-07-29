# Credential HMAC cutover

This minor release replaces unkeyed SHA-256 credential verifiers with
purpose-separated HMAC-SHA-256 verifiers derived from
`NEBULA_MGMT_MASTER_KEY`. It is a breaking, stopped-server upgrade. Do not run
old and new `nebula-mgmt` binaries together, and do not downgrade in place
after the migration.

The guide is included in the server archive and in Linux packages at
`/usr/share/doc/nebula-mgmt/upgrade-credential-hmac-cutover.md`.

## Impact

| State | Result after cutover | Required action |
|---|---|---|
| Local password bcrypt hash | Preserved | Sign in with the existing password. |
| OIDC binding and configuration | Preserved | Sign in through the identity provider. |
| TOTP secret | Preserved | Use the existing authenticator. |
| Web sessions | Invalidated | Sign in again. |
| Operator API keys | Invalidated | Mint a recovery key, then replace automation keys. |
| TOTP recovery codes | Deleted | Generate and store new codes after login. |
| Pending enrollment tokens | Invalidated | Mint replacement tokens. |
| Collecting mesh imports | Block the upgrade | Finish or cancel collection before upgrade. |
| Terminal mesh-import tokens | Scrubbed | No action. |
| Enrolled agents | Unaffected | No agent upgrade or re-enrollment is required. |

An API key restores REST/API automation only. It does not create a Web session
or reset TOTP. A disabled operator remains disabled after the cutover and after
a TOTP reset.

## Preflight

1. Confirm local shell access and the matching `NEBULA_MGMT_MASTER_KEY`. The
   key must decrypt the existing CA material; a different key cannot recover
   credentials or complete the upgrade.
2. Confirm at least one interactive login path: local password plus a working
   authenticator, or a working OIDC login. Existing recovery codes will be
   removed.
3. Finish or cancel every collecting mesh import on the old server. Migration
   refuses to start while collection is active and makes no database changes.
4. Stop every old `nebula-mgmt` process and wait for in-flight requests to
   finish. Rolling and mixed-version upgrades are unsupported.
5. Create a pre-upgrade backup with the old binary and retain its matching
   master key. See [Backup and restore](backup.md).

## Upgrade

1. Install the new minor release while the service remains stopped.
2. Start the new server once so it can run the cutover migration.
3. Mint a replacement admin API key from local access:

   ```sh
   nebula-mgmt ops mint-admin-key --config /etc/nebula-mgmt/server.yml
   ```

   Capture the key when it is printed; it is not shown again.
4. Replace every automation API key, create replacement enrollment and
   mesh-import tokens, sign in again, and generate replacement TOTP recovery
   codes.
5. Verify an interactive login, an API request using a replacement key, and an
   enrolled agent poll.

## Troubleshooting and recovery

**Master-key mismatch before migration.** Stop and supply the original
`NEBULA_MGMT_MASTER_KEY`. Do not substitute a new key: the new key cannot
decrypt CA material or match the verifier root.

**Collecting import blocks migration.** Start the old binary, finish or cancel
the collection, make a fresh backup, then retry the stopped-server upgrade. The
failed preflight did not modify the database.

**An old API key returns `401`.** This is expected. Use the locally minted
admin key, then replace the key used by that client.

**A Web session no longer works.** Sign in again with the preserved password
and TOTP authenticator or through OIDC. Generate new recovery codes after
login.

**The authenticator is lost and recovery codes were removed.** Stop the
service, then run the local break-glass command with the matching master key
and explicit confirmation:

```sh
nebula-mgmt ops reset-totp --config /etc/nebula-mgmt/server.yml --username <username> --confirm
```

Start the service, sign in with the existing password or OIDC binding, enroll a
new authenticator when required, and generate recovery codes. This reset does
not enable a disabled operator; an active admin must enable that account through
the normal Web or API path.

**An old binary rejects or writes legacy credentials.** Stop it. Post-cutover
database guards reject unversioned credential digests; return to the new binary
instead of trying a mixed-version repair.

**Restore-forward.** Restoring a pre-cutover archive with a newer binary runs
the cutover forward again. The restored copy needs the original master key and
new replacement credentials afterward.

**Rollback.** In-place downgrade is unsupported. Stop the new server, restore
the matching pre-upgrade database archive, and start the old binary with the
same `NEBULA_MGMT_MASTER_KEY`. Server-side changes made after the backup are
lost; agent files and certificates are not rolled back.
