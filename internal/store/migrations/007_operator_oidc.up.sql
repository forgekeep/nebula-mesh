ALTER TABLE operators ADD COLUMN oidc_subject TEXT NOT NULL DEFAULT '';
ALTER TABLE operators ADD COLUMN oidc_issuer  TEXT NOT NULL DEFAULT '';

-- Composite uniqueness is enforced at the application layer via
-- GetOperatorByOIDC (issuer+subject). A unique index would also work but
-- conflicts with the legacy empty default for local-only operators.
CREATE INDEX IF NOT EXISTS idx_operators_oidc ON operators(oidc_issuer, oidc_subject);
