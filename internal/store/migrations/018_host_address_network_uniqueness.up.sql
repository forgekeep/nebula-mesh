-- Restore network-scoped overlay-IP uniqueness.
--
-- Migration 001 enforced UNIQUE(network_id, nebula_ip) on the hosts table.
-- Migration 014 (multi_address) moved overlay addresses into host_addresses
-- and dropped that constraint without replacing it. That left validateHostIPs
-- (a read-then-check in the API layer) as the only guard, a TOCTOU window two
-- concurrent host creates can both pass, ending with two hosts bound to the
-- same overlay IP.
--
-- In a Nebula mesh that is a security defect, not merely a data-integrity one.
-- Two hosts sharing one overlay address means ambiguous routing and a CA that
-- has issued certificates letting one host receive another host's traffic
-- (interception or impersonation within the network).
--
-- host_addresses is keyed by host_id only, so a network-scoped UNIQUE index
-- needs network_id on the row. It is denormalized from hosts here. A host's
-- network_id is immutable after creation (no code path reassigns a host to a
-- different network), so the copy cannot drift.
--
-- The CREATE UNIQUE INDEX below FAILS if a database already holds two hosts
-- with the same overlay IP in one network. That is intentional and correct.
-- Such a row is the security defect described above, and refusing to start
-- until an operator resolves it (deciding which host keeps the address) is the
-- right fail-safe. There is no safe automatic answer to which host wins, so the
-- migration does not de-duplicate. The loader re-runs cleanly after the
-- operator removes the offending row (ADD COLUMN is tolerated as a duplicate
-- and the backfill UPDATE is idempotent).
ALTER TABLE host_addresses ADD COLUMN network_id TEXT NOT NULL DEFAULT '';

UPDATE host_addresses
   SET network_id = (SELECT h.network_id FROM hosts h WHERE h.id = host_addresses.host_id);

CREATE UNIQUE INDEX ux_host_addresses_network_address
    ON host_addresses (network_id, address);
