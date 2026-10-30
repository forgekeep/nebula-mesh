-- The Nebula release and OS a host's agent last reported (#400). The server
-- renders config for the host's Nebula version; an empty version means unknown
-- and selects the conservative config every supported release understands.
-- Only the agent runtime report writes these columns, so an operator edit,
-- which rewrites the host row, cannot overwrite a newer report with a stale one.
ALTER TABLE hosts ADD COLUMN nebula_version TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN nebula_os TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN nebula_reported_at DATETIME;
