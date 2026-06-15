-- Reverse 022_operator_lockout (#263). DROP COLUMN requires SQLite >= 3.35.
-- The migration loader is up-only, so this file documents the rollback and is
-- not executed at runtime.
ALTER TABLE operators DROP COLUMN locked_until;
ALTER TABLE operators DROP COLUMN failed_login_attempts;
