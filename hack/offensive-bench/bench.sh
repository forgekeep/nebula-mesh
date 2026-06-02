#!/usr/bin/env bash
#
# Local multi-operator offensive test bench for nebula-mesh (#208).
#
# Stands up a nebula-mgmt instance on loopback, seeds an admin plus two
# non-admin operators — each with their own CA, network, and hosts — and writes
# a creds file you can `source` to drive manual offensive checks (auth bypass,
# cross-tenant IDOR, issuance abuse, poll scoping). See README.md for the
# checklist mapped to the #178 objectives.
#
# Usage:
#   hack/offensive-bench/bench.sh up      # build, init, serve, provision
#   hack/offensive-bench/bench.sh creds   # print the creds file
#   hack/offensive-bench/bench.sh status  # server health + provisioned IDs
#   hack/offensive-bench/bench.sh down    # stop the server, keep the workdir
#   hack/offensive-bench/bench.sh clean   # stop and delete the workdir
#
# Everything lives under WORK (default ./.bench, override with BENCH_WORK).
# This is a developer tool for a throwaway loopback instance — never point it
# at real data.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="${BENCH_WORK:-$REPO_ROOT/.bench}"
LISTEN="${BENCH_LISTEN:-127.0.0.1:8080}"
SERVER="http://$LISTEN"
CONFIG="$WORK/config.yml"
CREDS="$WORK/creds.env"
PIDFILE="$WORK/mgmt.pid"
LOG="$WORK/mgmt.log"
MGMT="$WORK/bin/nebula-mgmt"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# id_of extracts the "(ID: xxx)" field printed by the create commands.
id_of() { sed -n 's/.*(ID: \([^,)]*\).*/\1/p' | head -n1; }

require() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

mgmt() { NEBULA_MGMT_MASTER_KEY="$MASTER_KEY" "$MGMT" "$@"; }

# api runs a provisioning command with the given operator key and returns stdout.
api() { mgmt "$@"; }

gen_master_key() {
	# 32 random bytes, base64 — the exact MasterKeySize the keystore expects.
	if command -v openssl >/dev/null 2>&1; then
		openssl rand -base64 32
	else
		head -c 32 /dev/urandom | base64
	fi
}

build() {
	log "building nebula-mgmt"
	mkdir -p "$WORK/bin" "$WORK/data"
	( cd "$REPO_ROOT" && go build -o "$MGMT" ./cmd/nebula-mgmt )
}

write_config() {
	cat >"$CONFIG" <<YAML
listen: "$LISTEN"
data_dir: "$WORK/data"
db_path: "$WORK/data/nebula.db"
ui_password: "bench-admin-pass"
log_level: "info"
allow_self_registration: false
YAML
}

wait_ready() {
	log "waiting for $SERVER/readyz"
	for _ in $(seq 1 50); do
		if curl -fsS "$SERVER/readyz" >/dev/null 2>&1; then return 0; fi
		sleep 0.2
	done
	die "server did not become ready — see $LOG"
}

# new_operator <username>: creates a non-admin operator, mints its API key, and
# creates a CA owned by that operator. Networks/hosts are admin-only (a host
# inherits its network's CA), so operator isolation is exercised through CA
# ownership — the cleanly testable tenant boundary on the API/CLI surface.
# Echoes:  <opID> <opKey> <caID>
new_operator() {
	local user="$1"
	local opID opKey caID
	opID=$(api user create -server "$SERVER" -api-key "$ADMIN_KEY" \
		-username "$user" -password 'Bench-Operator-Pass-1!' -role user | id_of)
	[ -n "$opID" ] || die "could not create operator $user"
	opKey=$(api apikey create -server "$SERVER" -api-key "$ADMIN_KEY" \
		-operator "$opID" -name "$user-key" | sed -n 's/^Token (shown once): //p')
	[ -n "$opKey" ] || die "could not mint api key for $user"
	caID=$(api ca create -server "$SERVER" -api-key "$opKey" -name "$user-ca" | id_of)
	[ -n "$caID" ] || die "could not create CA for $user"
	echo "$opID $opKey $caID"
}

new_network() {
	local name="$1" cidr="$2"
	api network create -server "$SERVER" -api-key "$ADMIN_KEY" -name "$name" -cidr "$cidr" | id_of
}

new_host() {
	local net="$1" name="$2" ip="$3"
	api host create -server "$SERVER" -api-key "$ADMIN_KEY" \
		-network "$net" -name "$name" -ip "$ip" | id_of
}

cmd_up() {
	require go; require curl
	mkdir -p "$WORK"
	[ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null && die "bench already running (pid $(cat "$PIDFILE")); run 'down' first"

	build
	MASTER_KEY="$(gen_master_key)"
	write_config

	log "init: migrate db + seed admin (capturing the one-time admin key)"
	local init_out
	init_out=$(mgmt init -config "$CONFIG")
	ADMIN_KEY=$(echo "$init_out" | awk 'f{print;exit} /Admin API key/{f=1}')
	[ -n "$ADMIN_KEY" ] || die "could not capture admin API key from init output"

	log "serve (background) → $LOG"
	NEBULA_MGMT_MASTER_KEY="$MASTER_KEY" nohup "$MGMT" serve -config "$CONFIG" >"$LOG" 2>&1 &
	echo $! >"$PIDFILE"
	wait_ready

	log "provisioning non-admin operators alice + bob (each owns a CA)"
	read -r ALICE_ID ALICE_KEY ALICE_CA < <(new_operator alice)
	read -r BOB_ID BOB_KEY BOB_CA < <(new_operator bob)

	log "provisioning admin-owned networks + hosts"
	local NET_A NET_B H_A1 H_A2 H_B1
	NET_A=$(new_network net-a 10.10.0.0/24)
	NET_B=$(new_network net-b 10.20.0.0/24)
	H_A1=$(new_host "$NET_A" host-a1 10.10.0.10)
	H_A2=$(new_host "$NET_A" host-a2 10.10.0.11)
	H_B1=$(new_host "$NET_B" host-b1 10.20.0.10)

	# Status-only block: a pending host has no certificate fingerprint yet, so
	# no blocklist row is written (the CA-scoped blocklist check needs an
	# enrolled host — see README). This still gives you a blocked-status host.
	log "blocking host-a2 (status change)"
	api host block -server "$SERVER" -api-key "$ADMIN_KEY" -id "$H_A2" >/dev/null || true

	cat >"$CREDS" <<ENV
# Source me:  source $CREDS
# admin owns the networks + hosts; alice and bob are non-admin operators that
# each own a CA. Tenant isolation is exercised via CA ownership and the
# admin-only gates (see hack/offensive-bench/README.md).
export BENCH_SERVER="$SERVER"
export BENCH_MASTER_KEY="$MASTER_KEY"
export BENCH_ADMIN_KEY="$ADMIN_KEY"
export BENCH_ALICE_ID="$ALICE_ID"
export BENCH_ALICE_KEY="$ALICE_KEY"
export BENCH_ALICE_CA="$ALICE_CA"
export BENCH_BOB_ID="$BOB_ID"
export BENCH_BOB_KEY="$BOB_KEY"
export BENCH_BOB_CA="$BOB_CA"
export BENCH_NET_A="$NET_A"
export BENCH_NET_B="$NET_B"
export BENCH_HOST_A1="$H_A1"
export BENCH_HOST_A2_BLOCKED="$H_A2"
export BENCH_HOST_B1="$H_B1"
ENV

	log "ready. admin UI: $SERVER/ui  (admin / bench-admin-pass)"
	log "creds written → $CREDS"
	echo
	cmd_creds
	echo
	log "next: source $CREDS  then see hack/offensive-bench/README.md"
}

cmd_creds() { [ -f "$CREDS" ] || die "no creds file — run 'up' first"; cat "$CREDS"; }

cmd_status() {
	if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
		log "server running (pid $(cat "$PIDFILE")) at $SERVER"
		curl -fsS "$SERVER/readyz" >/dev/null 2>&1 && echo "  /readyz: ok" || echo "  /readyz: NOT ok"
	else
		log "server not running"
	fi
	[ -f "$CREDS" ] && { echo; grep -E '^export' "$CREDS"; }
}

cmd_down() {
	if [ -f "$PIDFILE" ]; then
		local pid; pid="$(cat "$PIDFILE")"
		if kill -0 "$pid" 2>/dev/null; then log "stopping server (pid $pid)"; kill "$pid" 2>/dev/null || true; fi
		rm -f "$PIDFILE"
	else
		log "no pidfile; nothing to stop"
	fi
}

cmd_clean() { cmd_down; log "removing $WORK"; rm -rf "$WORK"; }

case "${1:-}" in
	up)     cmd_up ;;
	creds)  cmd_creds ;;
	status) cmd_status ;;
	down)   cmd_down ;;
	clean)  cmd_clean ;;
	*) echo "usage: $0 {up|creds|status|down|clean}" >&2; exit 2 ;;
esac
