CREATE TABLE IF NOT EXISTS networks (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    cidr        TEXT NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hosts (
    id              TEXT PRIMARY KEY,
    network_id      TEXT NOT NULL REFERENCES networks(id),
    name            TEXT NOT NULL,
    nebula_ip       TEXT NOT NULL,
    groups_json     TEXT NOT NULL DEFAULT '[]',
    role            TEXT NOT NULL DEFAULT 'host',
    is_lighthouse   BOOLEAN NOT NULL DEFAULT 0,
    is_relay        BOOLEAN NOT NULL DEFAULT 0,
    public_ip       TEXT,
    listen_port     INTEGER DEFAULT 4242,
    status          TEXT NOT NULL DEFAULT 'pending',
    cert_fingerprint TEXT,
    cert_expires_at  DATETIME,
    last_seen_at     DATETIME,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(network_id, name),
    UNIQUE(network_id, nebula_ip)
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id          TEXT PRIMARY KEY,
    host_id     TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    token       TEXT NOT NULL UNIQUE,
    used        BOOLEAN NOT NULL DEFAULT 0,
    expires_at  DATETIME NOT NULL,
    used_at     DATETIME,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS certificates (
    id              TEXT PRIMARY KEY,
    host_id         TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    fingerprint     TEXT NOT NULL UNIQUE,
    pem             TEXT NOT NULL,
    not_before      DATETIME NOT NULL,
    not_after       DATETIME NOT NULL,
    is_current      BOOLEAN NOT NULL DEFAULT 1,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocklist (
    fingerprint TEXT PRIMARY KEY,
    host_id     TEXT REFERENCES hosts(id),
    reason      TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS network_config (
    network_id  TEXT NOT NULL REFERENCES networks(id),
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    PRIMARY KEY (network_id, key)
);
