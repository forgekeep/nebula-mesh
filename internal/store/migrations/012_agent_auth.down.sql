-- SQLite before 3.35 cannot drop columns cleanly; the agent-auth columns are
-- left in place on rollback and simply unused.
DROP INDEX IF EXISTS idx_hosts_prev_fingerprint;
