package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

const operatorColumns = `id, username, display_name, password_hash, auth_provider, status, role, totp_secret, totp_enabled, oidc_issuer, oidc_subject, created_at, updated_at, last_login_at, failed_login_attempts, locked_until`

func scanOperator(scanner interface {
	Scan(dest ...any) error
}) (*models.Operator, error) {
	var op models.Operator
	var (
		lastLogin   sql.NullTime
		lockedUntil sql.NullTime
		totpEnabled int
	)
	if err := scanner.Scan(
		&op.ID, &op.Username, &op.DisplayName, &op.PasswordHash,
		&op.AuthProvider, &op.Status, &op.Role,
		&op.TOTPSecret, &totpEnabled,
		&op.OIDCIssuer, &op.OIDCSubject,
		&op.CreatedAt, &op.UpdatedAt, &lastLogin,
		&op.FailedLoginAttempts, &lockedUntil,
	); err != nil {
		return nil, err
	}
	op.TOTPEnabled = totpEnabled != 0
	if lastLogin.Valid {
		t := lastLogin.Time
		op.LastLoginAt = &t
	}
	if lockedUntil.Valid {
		t := lockedUntil.Time
		op.LockedUntil = &t
	}
	return &op, nil
}

// CreateOperator inserts a new operator. Caller fills in PasswordHash.
func (s *SQLiteStore) CreateOperator(ctx context.Context, op *models.Operator) error {
	if op.ID == "" || op.Username == "" || op.PasswordHash == "" {
		return fmt.Errorf("operator id, username, password_hash are required")
	}
	now := time.Now()
	if op.CreatedAt.IsZero() {
		op.CreatedAt = now
	}
	if op.UpdatedAt.IsZero() {
		op.UpdatedAt = now
	}
	if op.AuthProvider == "" {
		op.AuthProvider = models.OperatorAuthLocal
	}
	if op.Status == "" {
		op.Status = models.OperatorStatusActive
	}
	// Least privilege: a caller that wants an admin must say so. Defaulting
	// the empty string to admin would let any future caller that forgets to
	// set Role self-provision an administrator.
	if op.Role == "" {
		op.Role = models.OperatorRoleUser
	}
	if !models.ValidOperatorRole(op.Role) {
		return fmt.Errorf("invalid operator role %q", op.Role)
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO operators (id, username, display_name, password_hash, auth_provider, status, role, oidc_issuer, oidc_subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.Username, op.DisplayName, op.PasswordHash,
		op.AuthProvider, op.Status, op.Role,
		op.OIDCIssuer, op.OIDCSubject,
		op.CreatedAt, op.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert operator: %w", err)
	}
	return nil
}

// SeedInitialAdminOperator atomically inserts op (and key, if non-nil) only
// when the operators table is empty. The check-then-write is wrapped in a
// single transaction whose INSERT is guarded by `WHERE NOT EXISTS (SELECT 1
// FROM operators)`, so two concurrent first-boot seed calls cannot both
// succeed: the loser sees `RowsAffected() == 0` and returns (false, nil)
// without touching the API-key table.
//
// Returns (true, nil) if this call performed the seed; (false, nil) if the
// operators table already had at least one row (either because the caller
// ran a second time on a populated DB, or because a concurrent boot won
// the race). Any non-nil error indicates a real failure.
func (s *SQLiteStore) SeedInitialAdminOperator(ctx context.Context, op *models.Operator, key *models.OperatorAPIKey, rawKey string) (bool, error) {
	if op == nil {
		return false, fmt.Errorf("operator is required")
	}
	if op.ID == "" || op.Username == "" || op.PasswordHash == "" {
		return false, fmt.Errorf("operator id, username, password_hash are required")
	}
	now := time.Now()
	if op.CreatedAt.IsZero() {
		op.CreatedAt = now
	}
	if op.UpdatedAt.IsZero() {
		op.UpdatedAt = now
	}
	if op.AuthProvider == "" {
		op.AuthProvider = models.OperatorAuthLocal
	}
	if op.Status == "" {
		op.Status = models.OperatorStatusActive
	}
	// The seed only ever runs against an empty operators table, and the
	// first operator must be able to administer the server — admin is the
	// correct default here, unlike CreateOperator.
	if op.Role == "" {
		op.Role = models.OperatorRoleAdmin
	}
	if !models.ValidOperatorRole(op.Role) {
		return false, fmt.Errorf("invalid operator role %q", op.Role)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	// Conditional insert: succeeds (RowsAffected == 1) only on an empty
	// operators table. The race-loser's INSERT sees a non-empty table and
	// produces RowsAffected == 0 — no error, no row written.
	res, err := tx.ExecContext(ctx,
		`INSERT INTO operators (id, username, display_name, password_hash, auth_provider, status, role, oidc_issuer, oidc_subject, created_at, updated_at)
		 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		 WHERE NOT EXISTS (SELECT 1 FROM operators)`,
		op.ID, op.Username, op.DisplayName, op.PasswordHash,
		op.AuthProvider, op.Status, op.Role,
		op.OIDCIssuer, op.OIDCSubject,
		op.CreatedAt, op.UpdatedAt,
	)
	if err != nil {
		return false, fmt.Errorf("insert operator: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("seed admin operator rows: %w", err)
	}
	if rows == 0 {
		// Another caller already populated the operators table; nothing
		// to do, and we must NOT insert the API key under this op.ID
		// because that operator row does not exist.
		return false, nil
	}

	if key != nil {
		keyHash, err := s.credentialDigest(credentialhash.PurposeOperatorAPIKey, rawKey)
		if err != nil {
			return false, err
		}
		key.KeyHash = keyHash
		if key.ID == "" || key.OperatorID == "" {
			return false, fmt.Errorf("api key id and operator_id are required")
		}
		if key.CreatedAt.IsZero() {
			key.CreatedAt = now
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO operator_api_keys (id, operator_id, name, key_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
			key.ID, key.OperatorID, key.Name, keyHash, key.CreatedAt,
		); err != nil {
			return false, fmt.Errorf("insert api key: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit seed admin operator: %w", err)
	}
	return true, nil
}

// GetOperatorByOIDC returns the operator matching the issuer+subject pair, if
// any. Used to look up federated operators after a successful OIDC callback.
func (s *SQLiteStore) GetOperatorByOIDC(ctx context.Context, issuer, subject string) (*models.Operator, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+operatorColumns+` FROM operators WHERE oidc_issuer = ? AND oidc_subject = ?`,
		issuer, subject,
	)
	op, err := scanOperator(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get operator by oidc: %w", err)
	}
	return op, nil
}

func (s *SQLiteStore) GetOperator(ctx context.Context, id string) (*models.Operator, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+operatorColumns+` FROM operators WHERE id = ?`, id)
	op, err := scanOperator(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get operator: %w", err)
	}
	return op, nil
}

func (s *SQLiteStore) GetOperatorByUsername(ctx context.Context, username string) (*models.Operator, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+operatorColumns+` FROM operators WHERE username = ?`, username)
	op, err := scanOperator(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get operator by username: %w", err)
	}
	return op, nil
}

func (s *SQLiteStore) ListOperators(ctx context.Context) ([]*models.Operator, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+operatorColumns+` FROM operators ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list operators: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()
	var out []*models.Operator
	for rows.Next() {
		op, err := scanOperator(rows)
		if err != nil {
			return nil, fmt.Errorf("scan operator: %w", err)
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpdateOperatorPassword(ctx context.Context, id, passwordHash string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE operators SET password_hash=?, updated_at=? WHERE id=?`,
		passwordHash, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("update operator password: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update operator password rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) UpdateOperatorLastLogin(ctx context.Context, id string, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE operators SET last_login_at=?, updated_at=? WHERE id=?`, t, t, id)
	if err != nil {
		return fmt.Errorf("update last_login_at: %w", err)
	}
	return nil
}

// RecordFailedLoginAttempt increments the operator's consecutive failed-login
// counter and, when the count reaches maxAttempts, sets locked_until to
// lockUntil — atomically in one UPDATE so concurrent failures can't race past
// the threshold (#263). It reports whether the account is now locked.
func (s *SQLiteStore) RecordFailedLoginAttempt(ctx context.Context, id string, maxAttempts int, lockUntil time.Time) (bool, error) {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx,
		`UPDATE operators
		    SET failed_login_attempts = failed_login_attempts + 1,
		        locked_until = CASE WHEN failed_login_attempts + 1 >= ? THEN ? ELSE locked_until END,
		        updated_at = ?
		  WHERE id = ?`,
		maxAttempts, lockUntil, now, id); err != nil {
		return false, fmt.Errorf("record failed login: %w", err)
	}
	var locked sql.NullTime
	if err := s.db.QueryRowContext(ctx,
		`SELECT locked_until FROM operators WHERE id = ?`, id).Scan(&locked); err != nil {
		return false, fmt.Errorf("read lock state: %w", err)
	}
	return locked.Valid && locked.Time.After(now), nil
}

// ResetFailedLoginAttempts clears the failed-login counter and any active lock,
// called on a successful login and when an expired lock is observed (#263).
func (s *SQLiteStore) ResetFailedLoginAttempts(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE operators SET failed_login_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?`,
		time.Now(), id)
	if err != nil {
		return fmt.Errorf("reset failed login attempts: %w", err)
	}
	return nil
}

// DisableOperator marks operator as disabled and atomically deletes their
// sessions and revokes all of their non-revoked API keys.
func (s *SQLiteStore) DisableOperator(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	now := time.Now()
	result, err := tx.ExecContext(ctx,
		`UPDATE operators SET status=?, updated_at=? WHERE id=?`,
		models.OperatorStatusDisabled, now, id,
	)
	if err != nil {
		return fmt.Errorf("disable operator: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("disable operator rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM operator_sessions WHERE operator_id=?`, id); err != nil {
		return fmt.Errorf("delete operator sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE operator_api_keys SET revoked_at=? WHERE operator_id=? AND revoked_at IS NULL`,
		now, id,
	); err != nil {
		return fmt.Errorf("revoke operator api keys: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) EnableOperator(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE operators SET status=?, updated_at=? WHERE id=?`,
		models.OperatorStatusActive, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("enable operator: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("enable operator rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// --- TOTP / recovery codes ---

// SetOperatorTOTP records the operator's TOTP secret and enabled flag.
// Passing enabled=false with secret="" clears 2FA entirely.
func (s *SQLiteStore) SetOperatorTOTP(ctx context.Context, id, secret string, enabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	result, err := tx.ExecContext(ctx,
		`UPDATE operators SET totp_secret=?, totp_enabled=?, updated_at=? WHERE id=?`,
		secret, enabledInt, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("update totp: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update totp rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	if !enabled {
		if _, err := tx.ExecContext(ctx, `DELETE FROM operator_recovery_codes WHERE operator_id=?`, id); err != nil {
			return fmt.Errorf("clear recovery codes: %w", err)
		}
	}
	return tx.Commit()
}

// ResetOperatorTOTPBreakGlass disables TOTP for one operator, removes its
// recovery codes and sessions, and records the local recovery action in the
// same transaction. The operator status is deliberately unchanged.
func (s *SQLiteStore) ResetOperatorTOTPBreakGlass(ctx context.Context, username string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin TOTP reset: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback TOTP reset", "error", err)
		}
	}()

	var operatorID string
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM operators WHERE username = ?`, username).Scan(&operatorID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("find operator for TOTP reset: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE operators
		SET totp_secret = '', totp_enabled = 0, totp_last_timestep = 0, updated_at = ?
		WHERE id = ?`, time.Now(), operatorID); err != nil {
		return fmt.Errorf("reset operator TOTP: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM operator_recovery_codes WHERE operator_id = ?`, operatorID); err != nil {
		return fmt.Errorf("delete TOTP recovery codes: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM operator_sessions WHERE operator_id = ?`, operatorID); err != nil {
		return fmt.Errorf("delete operator sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log (id, actor, action, resource, details)
		VALUES ('audit_' || lower(hex(randomblob(16))), ?, ?, ?, ?)`,
		"ops-cli-break-glass", "operator.totp.reset", operatorID, "username="+username); err != nil {
		return fmt.Errorf("record TOTP reset audit: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit TOTP reset: %w", err)
	}
	return nil
}

// ReplaceOperatorRecoveryCodes deletes any existing codes for the operator
// and inserts the provided list of hashes (atomic).
func (s *SQLiteStore) ReplaceOperatorRecoveryCodes(ctx context.Context, id string, rawCodes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()
	if _, err := tx.ExecContext(ctx, `DELETE FROM operator_recovery_codes WHERE operator_id=?`, id); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	for _, rawCode := range rawCodes {
		h, err := s.credentialDigest(credentialhash.PurposeTOTPRecoveryCode, normalizeRecoveryCode(rawCode))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO operator_recovery_codes (operator_id, code_hash) VALUES (?, ?)`,
			id, h,
		); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return tx.Commit()
}

// ConsumeOperatorTOTPTimestep advances the operator's last-accepted TOTP
// timestep to ts, but only if ts is strictly greater than the stored value —
// the same atomic verify-and-mark shape as ConsumeOperatorRecoveryCode, so
// two concurrent logins presenting the same code cannot both win. Returns
// ErrTOTPReplayed when ts has already been used (or an older one accepted
// after it), which the caller must treat as an authentication failure
// (RFC 6238 §5.2).
func (s *SQLiteStore) ConsumeOperatorTOTPTimestep(ctx context.Context, id string, ts int64) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE operators SET totp_last_timestep=? WHERE id=? AND totp_last_timestep < ?`,
		ts, id, ts,
	)
	if err != nil {
		return fmt.Errorf("consume totp timestep: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("consume totp timestep rows: %w", err)
	}
	if rows == 0 {
		return ErrTOTPReplayed
	}
	return nil
}

// ConsumeOperatorRecoveryCode marks the given hash as consumed if it exists
// and is unused. Returns ErrNotFound otherwise.
func (s *SQLiteStore) ConsumeOperatorRecoveryCode(ctx context.Context, id, rawCode string) error {
	codeHash, err := s.credentialDigest(credentialhash.PurposeTOTPRecoveryCode, normalizeRecoveryCode(rawCode))
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE operator_recovery_codes SET consumed_at=? WHERE operator_id=? AND code_hash=? AND consumed_at IS NULL`,
		time.Now(), id, codeHash,
	)
	if err != nil {
		return fmt.Errorf("consume recovery code: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("consume recovery code rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ListOperatorRecoveryCodes returns the hashes of all non-consumed recovery
// codes for the operator. Used by tests and integrity checks.
func (s *SQLiteStore) ListOperatorRecoveryCodes(ctx context.Context, id string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT code_hash FROM operator_recovery_codes WHERE operator_id=? AND consumed_at IS NULL`,
		id,
	)
	if err != nil {
		return nil, fmt.Errorf("list recovery codes: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("scan recovery code: %w", err)
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// --- API keys ---

func (s *SQLiteStore) CreateOperatorAPIKey(ctx context.Context, k *models.OperatorAPIKey, rawKey string) error {
	if k == nil {
		return fmt.Errorf("api key is required")
	}
	keyHash, err := s.credentialDigest(credentialhash.PurposeOperatorAPIKey, rawKey)
	if err != nil {
		return err
	}
	if k.ID == "" || k.OperatorID == "" {
		return fmt.Errorf("api key id and operator_id are required")
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	k.KeyHash = keyHash
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO operator_api_keys (id, operator_id, name, key_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		k.ID, k.OperatorID, k.Name, keyHash, k.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert api key: %w", err)
	}
	return nil
}

// GetOperatorByAPIKey returns the operator associated with a non-revoked raw
// API key, ensuring the operator is active.
func (s *SQLiteStore) GetOperatorByAPIKey(ctx context.Context, rawKey string) (*models.Operator, *models.OperatorAPIKey, error) {
	keyHash, err := s.credentialDigest(credentialhash.PurposeOperatorAPIKey, rawKey)
	if err != nil {
		return nil, nil, err
	}
	var (
		k         models.OperatorAPIKey
		lastUsed  sql.NullTime
		revokedAt sql.NullTime
	)
	row := s.db.QueryRowContext(ctx,
		`SELECT id, operator_id, name, key_hash, created_at, last_used_at, revoked_at FROM operator_api_keys WHERE key_hash=? AND revoked_at IS NULL`,
		keyHash,
	)
	if err := row.Scan(&k.ID, &k.OperatorID, &k.Name, &k.KeyHash, &k.CreatedAt, &lastUsed, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, fmt.Errorf("get api key: %w", err)
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		k.LastUsedAt = &t
	}

	opRow := s.db.QueryRowContext(ctx, `SELECT `+operatorColumns+` FROM operators WHERE id = ?`, k.OperatorID)
	op, err := scanOperator(opRow)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("get operator: %w", err)
	}
	if op.Status != models.OperatorStatusActive {
		return nil, nil, ErrNotFound
	}
	return op, &k, nil
}

// GetOperatorAPIKey returns the API key by its ID regardless of revoked
// state. Callers that need ownership verification compare the returned
// .OperatorID against the expected operator.
func (s *SQLiteStore) GetOperatorAPIKey(ctx context.Context, keyID string) (*models.OperatorAPIKey, error) {
	var (
		k         models.OperatorAPIKey
		lastUsed  sql.NullTime
		revokedAt sql.NullTime
	)
	row := s.db.QueryRowContext(ctx,
		`SELECT id, operator_id, name, key_hash, created_at, last_used_at, revoked_at FROM operator_api_keys WHERE id=?`,
		keyID,
	)
	if err := row.Scan(&k.ID, &k.OperatorID, &k.Name, &k.KeyHash, &k.CreatedAt, &lastUsed, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get api key: %w", err)
	}
	if lastUsed.Valid {
		t := lastUsed.Time
		k.LastUsedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		k.RevokedAt = &t
	}
	return &k, nil
}

func (s *SQLiteStore) ListOperatorAPIKeys(ctx context.Context, operatorID string) ([]*models.OperatorAPIKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, operator_id, name, key_hash, created_at, last_used_at, revoked_at FROM operator_api_keys WHERE operator_id=? ORDER BY created_at DESC`,
		operatorID,
	)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()
	var out []*models.OperatorAPIKey
	for rows.Next() {
		var (
			k         models.OperatorAPIKey
			lastUsed  sql.NullTime
			revokedAt sql.NullTime
		)
		if err := rows.Scan(&k.ID, &k.OperatorID, &k.Name, &k.KeyHash, &k.CreatedAt, &lastUsed, &revokedAt); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		if lastUsed.Valid {
			t := lastUsed.Time
			k.LastUsedAt = &t
		}
		if revokedAt.Valid {
			t := revokedAt.Time
			k.RevokedAt = &t
		}
		out = append(out, &k)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) RevokeOperatorAPIKey(ctx context.Context, keyID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE operator_api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL`,
		time.Now(), keyID,
	)
	if err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke api key rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) TouchOperatorAPIKey(ctx context.Context, keyID string, t time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE operator_api_keys SET last_used_at=? WHERE id=?`, t, keyID)
	if err != nil {
		return fmt.Errorf("touch api key: %w", err)
	}
	return nil
}

// --- Sessions ---

func (s *SQLiteStore) CreateOperatorSession(ctx context.Context, sess *models.OperatorSession) error {
	if sess == nil {
		return fmt.Errorf("session is required")
	}
	tokenHash, err := s.credentialDigest(credentialhash.PurposeOperatorSession, sess.Token)
	if err != nil {
		return err
	}
	if sess.Token == "" || sess.OperatorID == "" {
		return fmt.Errorf("session token and operator_id are required")
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now()
	}
	state := sess.State
	if state == "" {
		state = models.SessionStateAuthenticated
	}
	// SEC-CREDENTIAL-001: the raw value lives solely in the operator's cookie,
	// never at rest.
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO operator_sessions (token_hash, operator_id, expires_at, created_at, state) VALUES (?, ?, ?, ?, ?)`,
		tokenHash, sess.OperatorID, sess.ExpiresAt, sess.CreatedAt, state,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// GetOperatorBySession returns the operator associated with a non-expired,
// fully-authenticated session whose operator is still active. Sessions in
// pending_totp state are NOT returned here.
func (s *SQLiteStore) GetOperatorBySession(ctx context.Context, token string) (*models.Operator, error) {
	tokenHash, err := s.credentialDigest(credentialhash.PurposeOperatorSession, token)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT operator_id, expires_at, state FROM operator_sessions WHERE token_hash=?`,
		tokenHash,
	)
	var (
		operatorID string
		expiresAt  time.Time
		state      models.SessionState
	)
	if err := row.Scan(&operatorID, &expiresAt, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
	}
	if state != models.SessionStateAuthenticated {
		return nil, ErrNotFound
	}
	if time.Now().After(expiresAt) {
		return nil, ErrNotFound
	}
	opRow := s.db.QueryRowContext(ctx, `SELECT `+operatorColumns+` FROM operators WHERE id=?`, operatorID)
	op, err := scanOperator(opRow)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get session operator: %w", err)
	}
	if op.Status != models.OperatorStatusActive {
		return nil, ErrNotFound
	}
	return op, nil
}

// GetPendingTwoFactorOperator returns the operator associated with a session
// that is awaiting a second factor (`pending_totp`). The operator must still
// be active. Sessions already authenticated are not returned.
func (s *SQLiteStore) GetPendingTwoFactorOperator(ctx context.Context, token string) (*models.Operator, error) {
	tokenHash, err := s.credentialDigest(credentialhash.PurposeOperatorSession, token)
	if err != nil {
		return nil, err
	}
	row := s.db.QueryRowContext(ctx,
		`SELECT operator_id, expires_at, state FROM operator_sessions WHERE token_hash=?`,
		tokenHash,
	)
	var (
		operatorID string
		expiresAt  time.Time
		state      models.SessionState
	)
	if err := row.Scan(&operatorID, &expiresAt, &state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get pending session: %w", err)
	}
	if state != models.SessionStatePendingTOTP {
		return nil, ErrNotFound
	}
	if time.Now().After(expiresAt) {
		return nil, ErrNotFound
	}
	opRow := s.db.QueryRowContext(ctx, `SELECT `+operatorColumns+` FROM operators WHERE id=?`, operatorID)
	op, err := scanOperator(opRow)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get pending session operator: %w", err)
	}
	if op.Status != models.OperatorStatusActive {
		return nil, ErrNotFound
	}
	return op, nil
}

// PromoteOperatorSession upgrades a pending_totp session to authenticated and
// resets the expiry to a fresh 24h window. Returns ErrNotFound if the session
// does not exist or is not pending.
func (s *SQLiteStore) PromoteOperatorSession(ctx context.Context, token string, newExpiry time.Time) error {
	tokenHash, err := s.credentialDigest(credentialhash.PurposeOperatorSession, token)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx,
		`UPDATE operator_sessions SET state=?, expires_at=? WHERE token_hash=? AND state=?`,
		models.SessionStateAuthenticated, newExpiry, tokenHash, models.SessionStatePendingTOTP,
	)
	if err != nil {
		return fmt.Errorf("promote session: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("promote session rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) DeleteOperatorSession(ctx context.Context, token string) error {
	tokenHash, err := s.credentialDigest(credentialhash.PurposeOperatorSession, token)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM operator_sessions WHERE token_hash=?`, tokenHash)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteOperatorSessionsByOperator(ctx context.Context, operatorID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM operator_sessions WHERE operator_id=?`, operatorID)
	if err != nil {
		return fmt.Errorf("delete sessions by operator: %w", err)
	}
	return nil
}

// DeleteOperatorSessionsByOperatorExcept removes every session of an operator
// except the one identified by keepToken, used by self-service password change
// to revoke other (possibly compromised) sessions while keeping the caller's
// current session alive (#259). keepToken is the raw cookie value; it is hashed
// here, mirroring DeleteOperatorSession.
func (s *SQLiteStore) DeleteOperatorSessionsByOperatorExcept(ctx context.Context, operatorID, keepToken string) error {
	tokenHash, err := s.credentialDigest(credentialhash.PurposeOperatorSession, keepToken)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`DELETE FROM operator_sessions WHERE operator_id=? AND token_hash<>?`,
		operatorID, tokenHash)
	if err != nil {
		return fmt.Errorf("delete sessions by operator except current: %w", err)
	}
	return nil
}

func normalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, " ", "")
	return strings.ReplaceAll(code, "-", "")
}

func (s *SQLiteStore) DeleteExpiredOperatorSessions(ctx context.Context, before time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM operator_sessions WHERE expires_at < ?`, before)
	if err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
	return nil
}
