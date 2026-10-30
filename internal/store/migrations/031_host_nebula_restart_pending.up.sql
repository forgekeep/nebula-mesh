-- When the host's agent reported that a delivered config changed keys Nebula
-- reads only at startup and Nebula has not restarted since (#400). NULL means
-- no restart is pending. Only the agent report and the operator's clear action
-- write this column, so an operator edit cannot bring back a stale value.
ALTER TABLE hosts ADD COLUMN nebula_restart_pending_at DATETIME;
