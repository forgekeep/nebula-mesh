CREATE TABLE IF NOT EXISTS oidc_login_states (
    digest BLOB PRIMARY KEY NOT NULL CHECK (length(digest) = 32),
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oidc_login_states_expires_at ON oidc_login_states(expires_at);
