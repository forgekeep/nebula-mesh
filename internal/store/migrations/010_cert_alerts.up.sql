CREATE TABLE IF NOT EXISTS cert_alerts (
    host_id            TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    alerted_not_after  DATETIME NOT NULL,
    alerted_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
