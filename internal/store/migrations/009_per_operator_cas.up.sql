CREATE TABLE IF NOT EXISTS cas (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    owner_operator_id      TEXT NOT NULL REFERENCES operators(id) ON DELETE RESTRICT,
    cert_pem               TEXT NOT NULL,
    fingerprint            TEXT NOT NULL UNIQUE,
    not_before             DATETIME NOT NULL,
    not_after              DATETIME NOT NULL,
    status                 TEXT NOT NULL DEFAULT 'active',
    encrypted_key_dek      BLOB NOT NULL,
    nonce_dek              BLOB NOT NULL,
    encrypted_key_material BLOB NOT NULL,
    nonce_key              BLOB NOT NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cas_owner ON cas(owner_operator_id);

ALTER TABLE networks     ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts        ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';
ALTER TABLE certificates ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';
ALTER TABLE blocklist    ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_networks_ca    ON networks(ca_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ca       ON hosts(ca_id);
CREATE INDEX IF NOT EXISTS idx_certificates_ca ON certificates(ca_id);
CREATE INDEX IF NOT EXISTS idx_blocklist_ca   ON blocklist(ca_id);
