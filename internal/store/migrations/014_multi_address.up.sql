-- Migrate to support multiple overlay addresses per host and multiple CIDRs per network.
-- Creates normalized tables for network_cidrs and host_addresses.
-- Backfills data from legacy columns, then drops them via table recreation.

-- Create new address tables.
CREATE TABLE network_cidrs (
  network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  position   INTEGER NOT NULL,
  cidr       TEXT NOT NULL,
  PRIMARY KEY (network_id, position)
);
CREATE INDEX idx_network_cidrs_network ON network_cidrs(network_id);

CREATE TABLE host_addresses (
  host_id  TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
  position INTEGER NOT NULL,
  address  TEXT NOT NULL,
  PRIMARY KEY (host_id, position)
);
CREATE INDEX idx_host_addresses_host ON host_addresses(host_id);
CREATE INDEX idx_host_addresses_address ON host_addresses(address);

-- Backfill from legacy columns at position 0.
INSERT INTO network_cidrs (network_id, position, cidr)
  SELECT id, 0, cidr FROM networks WHERE cidr IS NOT NULL AND cidr <> '';

INSERT INTO host_addresses (host_id, position, address)
  SELECT id, 0, nebula_ip FROM hosts WHERE nebula_ip IS NOT NULL AND nebula_ip <> '';

-- Drop legacy columns by recreating tables.
-- SQLite doesn't support DROP COLUMN directly with constraints, so we recreate.
PRAGMA foreign_keys = OFF;

-- Recreate networks table without cidr column.
CREATE TABLE networks_new (
  id              TEXT PRIMARY KEY,
  name            TEXT NOT NULL UNIQUE,
  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ca_id           TEXT NOT NULL DEFAULT '',
  config_version  INTEGER NOT NULL DEFAULT 1
);
INSERT INTO networks_new (id, name, created_at, ca_id, config_version)
  SELECT id, name, created_at, ca_id, config_version FROM networks;
DROP TABLE networks;
ALTER TABLE networks_new RENAME TO networks;
CREATE INDEX idx_networks_ca_id ON networks(ca_id);

-- Recreate hosts table without nebula_ip column.
CREATE TABLE hosts_new (
  id                  TEXT PRIMARY KEY,
  network_id          TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
  name                TEXT NOT NULL,
  groups_json         TEXT NOT NULL DEFAULT '[]',
  role                TEXT NOT NULL DEFAULT 'host',
  is_lighthouse       BOOLEAN NOT NULL DEFAULT 0,
  is_relay            BOOLEAN NOT NULL DEFAULT 0,
  public_ip           TEXT,
  listen_port         INTEGER DEFAULT 4242,
  status              TEXT NOT NULL DEFAULT 'pending',
  cert_fingerprint    TEXT,
  cert_expires_at     DATETIME,
  last_seen_at        DATETIME,
  created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  advanced_json       TEXT,
  ca_id               TEXT NOT NULL DEFAULT '',
  prev_cert_fingerprint TEXT,
  cert_rotated_at     DATETIME,
  pending_rekey       BOOLEAN NOT NULL DEFAULT 0,
  signing_pub_pem     TEXT,
  kind                TEXT NOT NULL DEFAULT 'agent',
  variant             TEXT NOT NULL DEFAULT '',
  config_version      INTEGER NOT NULL DEFAULT 0,
  UNIQUE(network_id, name)
);
INSERT INTO hosts_new (id, network_id, name, groups_json, role, is_lighthouse, is_relay, public_ip, listen_port, status, cert_fingerprint, cert_expires_at, last_seen_at, created_at, updated_at, advanced_json, ca_id, prev_cert_fingerprint, cert_rotated_at, pending_rekey, signing_pub_pem, kind, variant, config_version)
  SELECT id, network_id, name, groups_json, role, is_lighthouse, is_relay, public_ip, listen_port, status, cert_fingerprint, cert_expires_at, last_seen_at, created_at, updated_at, advanced_json, ca_id, prev_cert_fingerprint, cert_rotated_at, pending_rekey, signing_pub_pem, kind, variant, config_version FROM hosts;
DROP TABLE hosts;
ALTER TABLE hosts_new RENAME TO hosts;
CREATE INDEX idx_hosts_network_id ON hosts(network_id);
CREATE INDEX idx_hosts_cert_fingerprint ON hosts(cert_fingerprint);
CREATE INDEX idx_hosts_prev_cert_fingerprint ON hosts(prev_cert_fingerprint);
CREATE INDEX idx_hosts_status ON hosts(status);

PRAGMA foreign_keys = ON;
