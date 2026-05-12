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

const operatorColumns = `id, username, display_name, password_hash, auth_provider, status, role, created_at, updated_at, last_login_at`

func scanOperator(scanner interface {
	Scan(dest ...any) error
}) (*models.Operator, error) {
	var op models.Operator
	var lastLogin sql.NullTime
	if err := scanner.Scan(
		&op.ID, &op.Username, &op.DisplayName, &op.PasswordHash,
		&op.AuthProvider, &op.Status, &op.Role,
		&op.CreatedAt, &op.UpdatedAt, &lastLogin,
	); err != nil {
		return nil, err
	}
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
		`INSERT INTO operators (id, username, display_name, password_hash, auth_provider, status, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		op.ID, op.Username, op.DisplayName, op.PasswordHash,
		op.AuthProvider, op.Status, op.Role,
		op.CreatedAt, op.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert operator: %w", err)
	}
	return nil
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
	_, err := s.db.Exec(
		`INSERT INTO operator_sessions (token, operator_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
		sess.Token, sess.OperatorID, sess.ExpiresAt, sess.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

// GetOperatorBySession returns the operator associated with a non-expired session
// whose operator is still active. Expired sessions are not auto-deleted here.
func (s *SQLiteStore) GetOperatorBySession(_ context.Context, token string) (*models.Operator, error) {
	row := s.db.QueryRow(
		`SELECT operator_id, expires_at FROM operator_sessions WHERE token=?`,
		token,
	)
	var operatorID string
	var expiresAt time.Time
	if err := row.Scan(&operatorID, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get session: %w", err)
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
