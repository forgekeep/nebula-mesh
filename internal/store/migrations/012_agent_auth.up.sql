-- ADR 0004 (#75) — agent authorization model.
-- Adds the per-host fields needed for HTTP-signed polls, cert rotation overlap,
-- force-rotate (rekey) flow, and the Ed25519 signing public key registered at
-- enrollment.
ALTER TABLE hosts ADD COLUMN prev_cert_fingerprint TEXT;
ALTER TABLE hosts ADD COLUMN cert_rotated_at       DATETIME;
ALTER TABLE hosts ADD COLUMN pending_rekey         INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN signing_pub_pem       TEXT;

CREATE INDEX IF NOT EXISTS idx_hosts_prev_fingerprint ON hosts(prev_cert_fingerprint);
