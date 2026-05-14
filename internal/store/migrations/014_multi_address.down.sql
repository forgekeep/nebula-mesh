-- Rollback for 014_multi_address.
-- Restores legacy columns networks.cidr and hosts.nebula_ip from the new tables,
-- preserving only the position=0 records. Multi-address records (position > 0) are lost.
-- This is documented as an acceptable trade-off given the one-shot backfill design.

ALTER TABLE networks ADD COLUMN cidr TEXT;
ALTER TABLE hosts ADD COLUMN nebula_ip TEXT;

-- Restore legacy columns from position=0 records only.
UPDATE networks SET cidr = (
  SELECT cidr FROM network_cidrs WHERE network_cidrs.network_id = networks.id AND position = 0
);
UPDATE hosts SET nebula_ip = (
  SELECT address FROM host_addresses WHERE host_addresses.host_id = hosts.id AND position = 0
);

-- Add back the NOT NULL constraints (pre-014 schema had these).
ALTER TABLE networks ADD COLUMN cidr_temp TEXT NOT NULL DEFAULT '';
UPDATE networks SET cidr_temp = COALESCE(cidr, '');
ALTER TABLE networks DROP COLUMN cidr;
ALTER TABLE networks RENAME COLUMN cidr_temp TO cidr;

ALTER TABLE hosts ADD COLUMN nebula_ip_temp TEXT NOT NULL DEFAULT '';
UPDATE hosts SET nebula_ip_temp = COALESCE(nebula_ip, '');
ALTER TABLE hosts DROP COLUMN nebula_ip;
ALTER TABLE hosts RENAME COLUMN nebula_ip_temp TO nebula_ip;

-- Drop new tables.
DROP TABLE IF EXISTS host_addresses;
DROP TABLE IF EXISTS network_cidrs;
