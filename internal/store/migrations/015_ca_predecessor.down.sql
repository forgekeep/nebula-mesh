-- Rollback for 015_ca_predecessor.
-- Drops predecessor_id column from cas table.
-- SQLite doesn't support DROP COLUMN directly, so we recreate the table.

PRAGMA foreign_keys = OFF;

CREATE TABLE cas_new (
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

INSERT INTO cas_new (id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, created_at, updated_at)
  SELECT id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, created_at, updated_at FROM cas;

DROP TABLE cas;
ALTER TABLE cas_new RENAME TO cas;

CREATE INDEX idx_cas_owner ON cas(owner_operator_id);

PRAGMA foreign_keys = ON;
