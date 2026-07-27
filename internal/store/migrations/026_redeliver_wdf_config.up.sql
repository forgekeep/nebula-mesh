-- Force one config delivery after the v1.11 Windows compatibility defaults
-- changed the server renderer (#320). Existing hosts compare this value to
-- their last acknowledged config version during the next agent poll.
UPDATE networks SET config_version = config_version + 1;
