CREATE TABLE blocklist_old (
    fingerprint TEXT PRIMARY KEY,
    host_id     TEXT REFERENCES hosts(id),
    reason      TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO blocklist_old (fingerprint, host_id, reason, created_at)
SELECT fingerprint, host_id, reason, created_at FROM blocklist;

DROP TABLE blocklist;

ALTER TABLE blocklist_old RENAME TO blocklist;
