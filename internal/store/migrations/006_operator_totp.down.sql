DROP TABLE IF EXISTS operator_recovery_codes;
-- SQLite doesn't support DROP COLUMN cleanly before 3.35; leaving operators
-- columns in place on rollback is acceptable here.
