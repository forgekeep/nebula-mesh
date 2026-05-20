-- GHSA-ghmh-jhmj-wcmf: store SHA-256 of enrollment tokens at rest.
--
-- The old column held the raw token value; ConsumeToken looked it up by
-- equality, matching the (insecure) operator_api_keys pattern that was
-- later hashed in #41. Existing pending rows are kept in place — the
-- application layer now writes SHA-256 hex, so any unmigrated raw row
-- becomes lookup-unreachable on next consume and the host simply needs
-- a fresh token. That is the same outcome an operator would see after
-- a brief outage and is operationally acceptable for a short-TTL token.
ALTER TABLE enrollment_tokens RENAME COLUMN token TO token_hash;
