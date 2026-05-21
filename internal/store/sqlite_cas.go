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

const caColumns = `id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, predecessor_id, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, created_at, updated_at`

func scanCA(scanner interface {
	Scan(dest ...any) error
}) (*models.CA, error) {
	var c models.CA
	var predecessorID sql.NullString
	if err := scanner.Scan(
		&c.ID, &c.Name, &c.OwnerOperatorID, &c.CertPEM, &c.Fingerprint,
		&c.NotBefore, &c.NotAfter, &c.Status, &predecessorID,
		&c.EncryptedKeyDEK, &c.NonceDEK,
		&c.EncryptedKeyMaterial, &c.NonceKey,
		&c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if predecessorID.Valid {
		c.PredecessorID = &predecessorID.String
	}
	return &c, nil
}

func (s *SQLiteStore) CreateCA(ctx context.Context, c *models.CA) error {
	if c.ID == "" || c.Name == "" || c.OwnerOperatorID == "" || c.Fingerprint == "" {
		return fmt.Errorf("CA id, name, owner_operator_id, fingerprint are required")
	}
	if c.Status == "" {
		c.Status = models.CAStatusActive
	}
	now := time.Now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO cas (`+caColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.OwnerOperatorID, c.CertPEM, c.Fingerprint,
		c.NotBefore, c.NotAfter, c.Status, c.PredecessorID,
		c.EncryptedKeyDEK, c.NonceDEK,
		c.EncryptedKeyMaterial, c.NonceKey,
		c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert CA: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetCA(ctx context.Context, id string) (*models.CA, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE id = ?`, id)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get CA: %w", err)
	}
	return c, nil
}

func (s *SQLiteStore) GetCAByFingerprint(ctx context.Context, fp string) (*models.CA, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE fingerprint = ?`, fp)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get CA by fingerprint: %w", err)
	}
	return c, nil
}

func (s *SQLiteStore) ListCAs(ctx context.Context) ([]*models.CA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+caColumns+` FROM cas ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list CAs: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()
	var out []*models.CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan CA: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) ListCAsByOwner(ctx context.Context, ownerID string) ([]*models.CA, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+caColumns+` FROM cas WHERE owner_operator_id = ? ORDER BY name`, ownerID)
	if err != nil {
		return nil, fmt.Errorf("list CAs by owner: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()
	var out []*models.CA
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan CA: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) ListCAsApproachingExpiry(ctx context.Context, thresholdRatio float64) ([]*models.CA, error) {
	// Query for active CAs where remaining lifetime <= threshold * total lifetime.
	// SQLite stores times as RFC3339 strings, so we extract just the date portion (YYYY-MM-DD)
	// and use julianday() for date arithmetic.
	// Calculation: (not_after_days - now_days) / (not_after_days - not_before_days) <= threshold
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+caColumns+` FROM cas
		WHERE status = ?
		  AND (julianday(SUBSTR(not_after, 1, 10)) - julianday(SUBSTR(datetime('now'), 1, 10))) /
		       (julianday(SUBSTR(not_after, 1, 10)) - julianday(SUBSTR(not_before, 1, 10))) <= ?
		ORDER BY not_after ASC
	`, models.CAStatusActive, thresholdRatio)
	if err != nil {
		return nil, fmt.Errorf("list CAs approaching expiry: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()
	out := make([]*models.CA, 0)
	for rows.Next() {
		c, err := scanCA(rows)
		if err != nil {
			return nil, fmt.Errorf("scan CA: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) FindCAByPredecessor(ctx context.Context, predecessorID string) (*models.CA, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+caColumns+` FROM cas WHERE predecessor_id = ? AND status = ? LIMIT 1`, predecessorID, models.CAStatusActive)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find CA by predecessor: %w", err)
	}
	return c, nil
}

func (s *SQLiteStore) UpdateCAStatus(ctx context.Context, id string, status models.CAStatus) error {
	result, err := s.db.ExecContext(ctx, `UPDATE cas SET status=?, updated_at=? WHERE id=?`, status, time.Now(), id)
	if err != nil {
		return fmt.Errorf("update CA status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update CA status rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteCA removes a CA row. The DB-level ON DELETE RESTRICT on
// networks.ca_id (when enforced by application logic) is mirrored here:
// the call returns an error if networks still reference the CA, so the
// operator must retire / move networks first.
func (s *SQLiteStore) DeleteCA(ctx context.Context, id string) error {
	row := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM networks WHERE ca_id = ?`, id)
	var n int
	if err := row.Scan(&n); err != nil {
		return fmt.Errorf("check CA references: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("CA still has %d network(s); detach them first", n)
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM cas WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete CA: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete CA rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// CountEmptyCAIDRows counts the total number of rows across networks, hosts,
// certificates, and blocklist tables that have an empty ca_id. This is used
// at startup to detect rows from the pre-multi-CA era that have not been
// backfilled with a CA owner.
func (s *SQLiteStore) CountEmptyCAIDRows(ctx context.Context) (int, error) {
	const q = `
		SELECT
		  (SELECT COUNT(*) FROM networks WHERE ca_id IS NULL OR ca_id = '') +
		  (SELECT COUNT(*) FROM hosts WHERE ca_id IS NULL OR ca_id = '') +
		  (SELECT COUNT(*) FROM certificates WHERE ca_id IS NULL OR ca_id = '') +
		  (SELECT COUNT(*) FROM blocklist WHERE ca_id IS NULL OR ca_id = '')
	`
	var n int
	err := s.db.QueryRowContext(ctx, q).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count empty ca_id rows: %w", err)
	}
	return n, nil
}
