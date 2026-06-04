-- Down migration: revert column name. The application-layer application of
-- SHA-256 cannot be reversed; the column will simply contain hex hashes that
-- the (old) lookup-by-raw-token logic cannot match. Operators must
-- re-authenticate after downgrade.
ALTER TABLE operator_sessions RENAME COLUMN token_hash TO token;
