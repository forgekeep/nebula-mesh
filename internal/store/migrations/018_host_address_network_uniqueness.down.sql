-- Reverse 018: drop the uniqueness index and the denormalized network_id
-- column. The index must be dropped before the column it covers.
DROP INDEX IF EXISTS ux_host_addresses_network_address;
ALTER TABLE host_addresses DROP COLUMN network_id;
