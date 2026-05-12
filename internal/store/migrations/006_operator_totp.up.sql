ALTER TABLE operators ADD COLUMN totp_secret TEXT NOT NULL DEFAULT '';
ALTER TABLE operators ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS operator_recovery_codes (
    operator_id  TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    code_hash    TEXT NOT NULL,
    consumed_at  DATETIME,
    PRIMARY KEY (operator_id, code_hash)
);

-- Sessions can be either fully authenticated or pending a second factor.
ALTER TABLE operator_sessions ADD COLUMN state TEXT NOT NULL DEFAULT 'authenticated';
