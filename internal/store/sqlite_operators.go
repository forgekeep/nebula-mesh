package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
)

const operatorColumns = `id, username, display_name, password_hash, auth_provider, status, role, totp_secret, totp_enabled, oidc_issuer, oidc_subject, created_at, updated_at, last_login_at`

func scanOperator(scanner interface {
	Scan(dest ...any) error
}) (*models.Operator, error) {
	var op models.Operator
	var (
		lastLogin   sql.NullTime
		totpEnabled int
	)
	if err := scanner.Scan(
		&op.ID, &op.Username, &op.DisplayName, &op.PasswordHash,
		&op.AuthProvider, &op.Status, &op.Role,
		&op.TOTPSecret, &totpEnabled,
		&op.OIDCIssuer, &op.OIDCSubject,
		&op.CreatedAt, &op.UpdatedAt, &lastLogin,
	); err != nil {
		return nil, err
	}
	op.TOTPEnabled = totpEnabled != 0
	if lastLogin.Valid {
		t := lastLogin.Time
		op.LastLoginAt = &t
	}
	return &op, nil
}

// CreateOperator inserts a new operator. Caller fills in PasswordHash.
func (s *SQLiteStore) CreateOperator(_ context.Context, op *models.Operator) error {
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
	if op.Role == "" {
		op.Role = "admin"
	}
	_, err := s.db.Exec(
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

// GetOperatorByOIDC returns the operator matching the issuer+subject pair, if
// any. Used to look up federated operators after a successful OIDC callback.
func (s *SQLiteStore) GetOperatorByOIDC(_ context.Context, issuer, subject string) (*models.Operator, error) {
	row := s.db.QueryRow(
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

func (s *SQLiteStore) GetOperator(_ context.Context, id string) (*models.Operator, error) {
	row := s.db.QueryRow(`SELECT `+operatorColumns+` FROM operators WHERE id = ?`, id)
	op, err := scanOperator(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get operator: %w", err)
	}
	return op, nil
}

func (s *SQLiteStore) GetOperatorByUsername(_ context.Context, username string) (*models.Operator, error) {
	row := s.db.QueryRow(`SELECT `+operatorColumns+` FROM operators WHERE username = ?`, username)
	op, err := scanOperator(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get operator by username: %w", err)
	}
	return op, nil
}

func (s *SQLiteStore) ListOperators(_ context.Context) ([]*models.Operator, error) {
	rows, err := s.db.Query(`SELECT ` + operatorColumns + ` FROM operators ORDER BY username`)
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

func (s *SQLiteStore) UpdateOperatorPassword(_ context.Context, id, passwordHash string) error {
	result, err := s.db.Exec(
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

func (s *SQLiteStore) UpdateOperatorLastLogin(_ context.Context, id string, t time.Time) error {
	_, err := s.db.Exec(`UPDATE operators SET last_login_at=?, updated_at=? WHERE id=?`, t, t, id)
	if err != nil {
		return fmt.Errorf("update last_login_at: %w", err)
	}
	return nil
}

// DisableOperator marks operator as disabled and atomically deletes their
// sessions and revokes all of their non-revoked API keys.
func (s *SQLiteStore) DisableOperator(_ context.Context, id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	now := time.Now()
	result, err := tx.Exec(
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

	if _, err := tx.Exec(`DELETE FROM operator_sessions WHERE operator_id=?`, id); err != nil {
		return fmt.Errorf("delete operator sessions: %w", err)
	}
	if _, err := tx.Exec(
		`UPDATE operator_api_keys SET revoked_at=? WHERE operator_id=? AND revoked_at IS NULL`,
		now, id,
	); err != nil {
		return fmt.Errorf("revoke operator api keys: %w", err)
	}

	return tx.Commit()
}

func (s *SQLiteStore) EnableOperator(_ context.Context, id string) error {
	result, err := s.db.Exec(
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
func (s *SQLiteStore) SetOperatorTOTP(_ context.Context, id, secret string, enabled bool) error {
	tx, err := s.db.Begin()
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
	result, err := tx.Exec(
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
		if _, err := tx.Exec(`DELETE FROM operator_recovery_codes WHERE operator_id=?`, id); err != nil {
			return fmt.Errorf("clear recovery codes: %w", err)
		}
	}
	return tx.Commit()
}

// ReplaceOperatorRecoveryCodes deletes any existing codes for the operator
// and inserts the provided list of hashes (atomic).
func (s *SQLiteStore) ReplaceOperatorRecoveryCodes(_ context.Context, id string, codeHashes []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()
	if _, err := tx.Exec(`DELETE FROM operator_recovery_codes WHERE operator_id=?`, id); err != nil {
		return fmt.Errorf("delete recovery codes: %w", err)
	}
	for _, h := range codeHashes {
		if _, err := tx.Exec(
			`INSERT INTO operator_recovery_codes (operator_id, code_hash) VALUES (?, ?)`,
			id, h,
		); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	return tx.Commit()
}

// ConsumeOperatorRecoveryCode marks the given hash as consumed if it exists
// and is unused. Returns ErrNotFound otherwise.
func (s *SQLiteStore) ConsumeOperatorRecoveryCode(_ context.Context, id, codeHash string) error {
	result, err := s.db.Exec(
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
func (s *SQLiteStore) ListOperatorRecoveryCodes(_ context.Context, id string) ([]string, error) {
	rows, err := s.db.Query(
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

func (s *SQLiteStore) CreateOperatorAPIKey(_ context.Context, k *models.OperatorAPIKey) error {
	if k.ID == "" || k.OperatorID == "" || k.KeyHash == "" {
		return fmt.Errorf("api key id, operator_id, key_hash are required")
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now()
	}
	_, err := s.db.Exec(
		`INSERT INTO operator_api_keys (id, operator_id, name, key_hash, created_at) VALUES (?, ?, ?, ?, ?)`,
		k.ID, k.OperatorID, k.Name, k.KeyHash, k.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert api key: %w", err)
	}
	return nil
}

// GetOperatorByAPIKeyHash returns the operator associated with a non-revoked
// API key, ensuring the operator is active.
func (s *SQLiteStore) GetOperatorByAPIKeyHash(_ context.Context, keyHash string) (*models.Operator, *models.OperatorAPIKey, error) {
	var (
		k          models.OperatorAPIKey
		lastUsed   sql.NullTime
		revokedAt  sql.NullTime
	)
	row := s.db.QueryRow(
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

	opRow := s.db.QueryRow(`SELECT `+operatorColumns+` FROM operators WHERE id = ?`, k.OperatorID)
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

func (s *SQLiteStore) ListOperatorAPIKeys(_ context.Context, operatorID string) ([]*models.OperatorAPIKey, error) {
	rows, err := s.db.Query(
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

func (s *SQLiteStore) RevokeOperatorAPIKey(_ context.Context, keyID string) error {
	result, err := s.db.Exec(
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

func (s *SQLiteStore) TouchOperatorAPIKey(_ context.Context, keyID string, t time.Time) error {
	_, err := s.db.Exec(`UPDATE operator_api_keys SET last_used_at=? WHERE id=?`, t, keyID)
	if err != nil {
		return fmt.Errorf("touch api key: %w", err)
	}
	return nil
}

// --- Sessions ---

func (s *SQLiteStore) CreateOperatorSession(_ context.Context, sess *models.OperatorSession) error {
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
	_, err := s.db.Exec(
		`INSERT INTO operator_sessions (token, operator_id, expires_at, created_at, state) VALUES (?, ?, ?, ?, ?)`,
		sess.Token, sess.OperatorID, sess.ExpiresAt, sess.CreatedAt, state,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// GetOperatorBySession returns the operator associated with a non-expired,
// fully-authenticated session whose operator is still active. Sessions in
// pending_totp state are NOT returned here.
func (s *SQLiteStore) GetOperatorBySession(_ context.Context, token string) (*models.Operator, error) {
	row := s.db.QueryRow(
		`SELECT operator_id, expires_at, state FROM operator_sessions WHERE token=?`,
		token,
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
	opRow := s.db.QueryRow(`SELECT `+operatorColumns+` FROM operators WHERE id=?`, operatorID)
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
func (s *SQLiteStore) GetPendingTwoFactorOperator(_ context.Context, token string) (*models.Operator, error) {
	row := s.db.QueryRow(
		`SELECT operator_id, expires_at, state FROM operator_sessions WHERE token=?`,
		token,
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
	opRow := s.db.QueryRow(`SELECT `+operatorColumns+` FROM operators WHERE id=?`, operatorID)
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
func (s *SQLiteStore) PromoteOperatorSession(_ context.Context, token string, newExpiry time.Time) error {
	result, err := s.db.Exec(
		`UPDATE operator_sessions SET state=?, expires_at=? WHERE token=? AND state=?`,
		models.SessionStateAuthenticated, newExpiry, token, models.SessionStatePendingTOTP,
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

func (s *SQLiteStore) DeleteOperatorSession(_ context.Context, token string) error {
	_, err := s.db.Exec(`DELETE FROM operator_sessions WHERE token=?`, token)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteOperatorSessionsByOperator(_ context.Context, operatorID string) error {
	_, err := s.db.Exec(`DELETE FROM operator_sessions WHERE operator_id=?`, operatorID)
	if err != nil {
		return fmt.Errorf("delete sessions by operator: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteExpiredOperatorSessions(_ context.Context, before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM operator_sessions WHERE expires_at < ?`, before)
	if err != nil {
		return fmt.Errorf("delete expired sessions: %w", err)
	}
	return nil
}
