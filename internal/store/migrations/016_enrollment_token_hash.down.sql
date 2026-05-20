-- Down migration: revert column name. The application-layer
-- application of SHA-256 cannot be reversed; the column will simply
-- contain hex hashes that the (old) lookup-by-equality logic cannot
-- match. Operators must regenerate tokens after downgrade.
ALTER TABLE enrollment_tokens RENAME COLUMN token_hash TO token;
