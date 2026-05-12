CREATE TABLE IF NOT EXISTS operators (
    id             TEXT PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    display_name   TEXT NOT NULL DEFAULT '',
    password_hash  TEXT NOT NULL,
    auth_provider  TEXT NOT NULL DEFAULT 'local',
    status         TEXT NOT NULL DEFAULT 'active',
    role           TEXT NOT NULL DEFAULT 'admin',
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at  DATETIME
);

CREATE TABLE IF NOT EXISTS operator_api_keys (
    id           TEXT PRIMARY KEY,
    operator_id  TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    key_hash     TEXT NOT NULL UNIQUE,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    revoked_at   DATETIME
);

CREATE INDEX IF NOT EXISTS idx_op_api_keys_operator ON operator_api_keys(operator_id);

CREATE TABLE IF NOT EXISTS operator_sessions (
    token        TEXT PRIMARY KEY,
    operator_id  TEXT NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    expires_at   DATETIME NOT NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_op_sessions_operator ON operator_sessions(operator_id);
CREATE INDEX IF NOT EXISTS idx_op_sessions_expires ON operator_sessions(expires_at);
