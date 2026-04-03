-- Recreate blocklist with ON DELETE SET NULL for host_id FK.
-- SQLite does not support ALTER FOREIGN KEY, so we recreate the table.
CREATE TABLE blocklist_new (
    fingerprint TEXT PRIMARY KEY,
    host_id     TEXT REFERENCES hosts(id) ON DELETE SET NULL,
    reason      TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO blocklist_new (fingerprint, host_id, reason, created_at)
SELECT fingerprint, host_id, reason, created_at FROM blocklist;

DROP TABLE blocklist;

ALTER TABLE blocklist_new RENAME TO blocklist;
