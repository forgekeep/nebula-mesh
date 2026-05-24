-- GHSA-v2jf-442r-6mjh: durable replay protection for signed agent polls.
--
-- The in-memory LRU at internal/api/pop/nonce.go was vulnerable to
-- restart replay (process restart wipes the cache; captured nonces
-- become acceptable again within the timestamp skew window) and to
-- eviction replay (one hostile host could flood >65,536 distinct
-- nonces to evict a victim host's recorded nonce from the global
-- LRU). Persisting nonces in SQLite keyed by (host_id, nonce) with
-- explicit expiry closes both. expires_at is stored as a unix epoch
-- INTEGER so the prune sweep WHERE expires_at < ? is index-friendly.
-- Rows past expiry are pruned lazily by SeenOrAddPopNonce on insert.
CREATE TABLE IF NOT EXISTS pop_nonces (
    host_id    TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (host_id, nonce)
);
CREATE INDEX IF NOT EXISTS idx_pop_nonces_expires_at
    ON pop_nonces (expires_at);
