-- Track the last TOTP timestep each operator successfully authenticated
-- with, so an observed code cannot be replayed inside its ~90s acceptance
-- window (period 30s, skew 1). RFC 6238 §5.2 requires the verifier to
-- reject a second use of the same or an earlier timestep; recovery codes
-- were already consumed atomically but TOTP codes were not.
ALTER TABLE operators ADD COLUMN totp_last_timestep INTEGER NOT NULL DEFAULT 0;
