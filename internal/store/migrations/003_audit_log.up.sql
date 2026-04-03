CREATE TABLE IF NOT EXISTS audit_log (
    id         TEXT PRIMARY KEY,
    timestamp  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    resource   TEXT NOT NULL,
    details    TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
