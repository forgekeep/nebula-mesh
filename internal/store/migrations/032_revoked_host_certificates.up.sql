-- SEC-PERSIST-001: the store creates this index and backfills revocations
-- in the same transaction as the migration marker.
CREATE INDEX IF NOT EXISTS idx_certificates_host ON certificates(host_id);
