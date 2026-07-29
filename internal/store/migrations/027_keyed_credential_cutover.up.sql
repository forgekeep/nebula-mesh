-- SEC-CREDENTIAL-001: plain SHA-256 credential verifiers are offline password
-- or token oracles after a database disclosure. This one-way cutover removes
-- credentials that cannot be re-keyed without their plaintext.
DELETE FROM operator_sessions;
DELETE FROM operator_recovery_codes;
DELETE FROM enrollment_tokens;

UPDATE operator_api_keys
SET key_hash = 'cutover-v1:api-key:' || id,
    revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP);

UPDATE mesh_imports
SET token_hash = 'cutover-v1:mesh-import:' || id
WHERE status IN ('finalized', 'canceled');
