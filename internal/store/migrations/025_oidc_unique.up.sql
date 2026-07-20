-- Enforce uniqueness of the OIDC (issuer, subject) pair at the DB level.
-- The partial index excludes local-only operators whose oidc_issuer and
-- oidc_subject are both empty strings (#295).
CREATE UNIQUE INDEX IF NOT EXISTS ux_operators_oidc
    ON operators(oidc_issuer, oidc_subject)
    WHERE oidc_issuer != '' AND oidc_subject != '';
