-- Managed webhook subscriptions (#256 phase 2). Each row is one operator-owned
-- delivery target: a URL, an event-type filter (comma-separated; empty = all),
-- and an optional HMAC secret stored envelope-encrypted under the master key
-- (same two-layer scheme as cas: a per-row DEK wrapped under the master, the
-- secret sealed under the DEK). Delivery-status columns give per-subscription
-- observability.

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id                   TEXT PRIMARY KEY,
    owner_operator_id    TEXT NOT NULL REFERENCES operators(id) ON DELETE RESTRICT,
    url                  TEXT NOT NULL,
    events               TEXT NOT NULL DEFAULT '',   -- comma-separated; empty = all events
    active               INTEGER NOT NULL DEFAULT 1,
    allow_private        INTEGER NOT NULL DEFAULT 0,

    -- Optional HMAC secret, envelope-encrypted. NULL columns => unsigned deliveries.
    encrypted_secret_dek BLOB,
    nonce_dek            BLOB,
    encrypted_secret     BLOB,
    nonce_secret         BLOB,

    -- Per-subscription delivery observability.
    last_delivery_at     DATETIME,
    last_status          TEXT NOT NULL DEFAULT '',   -- '' | 'ok' | 'failed'
    last_error           TEXT NOT NULL DEFAULT '',
    consecutive_failures INTEGER NOT NULL DEFAULT 0,

    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webhook_subs_owner  ON webhook_subscriptions(owner_operator_id);
CREATE INDEX IF NOT EXISTS idx_webhook_subs_active ON webhook_subscriptions(active) WHERE active = 1;
