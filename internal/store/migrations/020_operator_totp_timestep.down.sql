-- Down migration: removes per-operator TOTP replay protection.
--
-- After downgrade the totp_last_timestep column is gone, so an attacker who
-- observed a valid TOTP code can replay it within its ~90s acceptance window
-- (period 30s, skew 1) until the column is restored. Operator rows are
-- otherwise unaffected.
ALTER TABLE operators DROP COLUMN totp_last_timestep;
