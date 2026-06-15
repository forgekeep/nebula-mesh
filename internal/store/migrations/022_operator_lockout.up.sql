-- Per-account login lockout (#263). failed_login_attempts counts consecutive
-- failed password logins; locked_until, when in the future, blocks login
-- regardless of credentials. Both reset on a successful login and when an
-- expired lock is observed. NULL locked_until means "not locked".
ALTER TABLE operators ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operators ADD COLUMN locked_until DATETIME;
