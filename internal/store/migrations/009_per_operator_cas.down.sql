-- SQLite before 3.35 cannot drop columns cleanly; the ca_id columns are
-- left in place on rollback and simply unused.
DROP INDEX IF EXISTS idx_blocklist_ca;
DROP INDEX IF EXISTS idx_certificates_ca;
DROP INDEX IF EXISTS idx_hosts_ca;
DROP INDEX IF EXISTS idx_networks_ca;
DROP INDEX IF EXISTS idx_cas_owner;
DROP TABLE IF EXISTS cas;
