# Offensive test bench

A reproducible local bench for manual offensive testing of `nebula-mgmt`
(#208). It stands up a throwaway instance on loopback and seeds a realistic
multi-operator topology so you can attack tenancy, authz, issuance, and poll
scoping by hand.

> Developer tool only. It runs a plaintext loopback instance with a throwaway
> master key under `./.bench`. Never point it at real data.

## What it provisions

- `nebula-mgmt` on `127.0.0.1:8080`, fresh SQLite DB, random master key.
- **admin** — seeded by `init`; UI login `admin` / `bench-admin-pass`.
- **alice** (role `user`) — API key, owns CA `alice-ca`.
- **bob** (role `user`) — API key, owns CA `bob-ca`.
- **admin-owned**: networks `net-a` (`10.10.0.0/24`), `net-b` (`10.20.0.0/24`);
  hosts `host-a1`, `host-a2` (blocked — status only), `host-b1`.

Networks and host creation are admin-only, and a host inherits its network's CA,
so the cleanly scriptable tenant boundary is **CA ownership** (alice-ca vs
bob-ca) plus the **admin-role gates**. The two non-admin operators each own a
disjoint CA — the setup for cross-tenant and privilege-escalation checks.

## Run

```sh
make bench-up          # or: hack/offensive-bench/bench.sh up
source .bench/creds.env
# ... run the checks below ...
make bench-down        # stop server   (make bench-clean to also wipe ./.bench)
```

`creds.env` exports `BENCH_SERVER`, `BENCH_ADMIN_KEY`, and per-operator
`BENCH_ALICE_*` / `BENCH_BOB_*` (key, CA, network, host IDs).

A helper for authenticated calls:

```sh
as() { key="$1"; shift; curl -s -H "Authorization: Bearer $key" "$@"; }
```

## Offensive checklist (mapped to the #178 objectives)

A helper for HTTP status:

```sh
code() { curl -s -o /dev/null -w '%{http_code}\n' "$@"; }
```

### Objective 4 — tenant isolation (cross-tenant IDOR)
Bob (non-admin) must not read another operator's CA, nor admin-owned hosts.

```sh
# bob reads alice's CA → expect 403, and bob's CA list never shows alice's CA
code -H "Authorization: Bearer $BENCH_BOB_KEY" "$BENCH_SERVER/api/v1/cas/$BENCH_ALICE_CA"   # 403
as "$BENCH_BOB_KEY" "$BENCH_SERVER/api/v1/cas" | grep -c "$BENCH_ALICE_CA"                   # 0
# bob reads an admin-owned host → expect 403/404, and bob's host list is empty of it
code -H "Authorization: Bearer $BENCH_BOB_KEY" "$BENCH_SERVER/api/v1/hosts/$BENCH_HOST_A1"   # 403
as "$BENCH_BOB_KEY" "$BENCH_SERVER/api/v1/hosts" | grep -c "$BENCH_HOST_A1"                  # 0
```

### Objective 2 — host-management takeover
Bob must not block / rotate / re-enroll / mint a bundle for a host he does not own.

```sh
for path in block unblock rotate-cert reenroll mobile-bundle enrollment-token; do
  printf '%-16s ' "$path"
  code -X POST -H "Authorization: Bearer $BENCH_BOB_KEY" \
       "$BENCH_SERVER/api/v1/hosts/$BENCH_HOST_A1/$path"   # expect 403
done
# bob editing an admin-owned network's firewall → expect 403
code -X PUT -H "Authorization: Bearer $BENCH_BOB_KEY" \
   -H 'Content-Type: application/json' -d '{"inbound":[],"outbound":[]}' \
   "$BENCH_SERVER/api/v1/networks/$BENCH_NET_A/firewall"
```

### Auth bypass / privilege escalation
```sh
# no key / garbage key → 401
curl -s -o /dev/null -w '%{http_code}\n' "$BENCH_SERVER/api/v1/hosts"
as deadbeef -o /dev/null -w '%{http_code}\n' "$BENCH_SERVER/api/v1/hosts"
# non-admin hitting admin-only endpoints → 403
as "$BENCH_BOB_KEY" -o /dev/null -w '%{http_code}\n' "$BENCH_SERVER/api/v1/operators"
as "$BENCH_BOB_KEY" -o /dev/null -w '%{http_code}\n' "$BENCH_SERVER/api/v1/audit-log"
as "$BENCH_BOB_KEY" -o /dev/null -w '%{http_code}\n' "$BENCH_SERVER/api/v1/settings"
```

### Objective 1 — key extraction (at-rest inspection)
CA private keys must be encrypted at rest; the master key must not be in the DB.

```sh
# No PEM private-key material in the DB; CA key columns are ciphertext.
strings .bench/data/nebula.db | grep -i 'PRIVATE KEY' && echo 'LEAK' || echo 'no plaintext key'
```

### Objective 3 — network access / poll scoping
The blocklist an agent receives must be scoped to its own CA (#203).

The bench blocks a **pending** host (`host-a2`), which changes status only — a
blocklist row is written when a host with a *certificate* is blocked, so this
check needs an enrolled agent. To exercise it:

1. Enroll a `nebula-agent` against `net-a` so the host gets a certificate.
2. Block that host (`nebula-mgmt host block ...`).
3. Inspect the row and confirm `ca_id` is the network's CA, not empty/global:

```sh
sqlite3 .bench/data/nebula.db "SELECT fingerprint, ca_id FROM blocklist;"
```

4. Poll `/api/v1/agent/updates` from an agent under a *different* CA and confirm
   that fingerprint is **absent** from its `blocklist` field.

## Notes

- Re-running `up` while the server is up is refused; run `down` first.
- Logs: `.bench/mgmt.log`. The workdir (`./.bench`) is git-ignored-friendly —
  delete it with `make bench-clean`.
