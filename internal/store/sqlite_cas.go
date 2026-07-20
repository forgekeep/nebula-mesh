package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

const (
	caColumns                  = `id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, predecessor_id, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, created_at, updated_at`
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintUnique     = 2067
)

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
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO cas (`+caColumns+`)
		 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		 WHERE NOT EXISTS (
			SELECT 1 FROM mesh_imports
			WHERE ca_id = COALESCE(?, '') AND status = ?
		 )`,
		c.ID, c.Name, c.OwnerOperatorID, c.CertPEM, c.Fingerprint,
		c.NotBefore, c.NotAfter, c.Status, c.PredecessorID,
		c.EncryptedKeyDEK, c.NonceDEK,
		c.EncryptedKeyMaterial, c.NonceKey,
		c.CreatedAt, c.UpdatedAt, c.PredecessorID, models.MeshImportStatusCollecting,
	)
	if err != nil {
		var sqliteErr interface{ Code() int }
		if errors.As(err, &sqliteErr) && (sqliteErr.Code() == sqliteConstraintUnique || sqliteErr.Code() == sqliteConstraintPrimaryKey) {
			return fmt.Errorf("insert CA: %w", ErrDuplicateEntry)
		}
		return fmt.Errorf("insert CA: %w", err)
	}
	if rows, err := result.RowsAffected(); err != nil {
		return fmt.Errorf("insert CA rows: %w", err)
	} else if rows == 0 {
		return ErrMeshImportInProgress
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
	result, err := s.db.ExecContext(ctx, `UPDATE cas SET status=?, updated_at=?
		WHERE id=? AND NOT EXISTS (
			SELECT 1 FROM mesh_imports WHERE ca_id = ? AND status = ?
		)`, status, time.Now(), id, id, models.MeshImportStatusCollecting)
	if err != nil {
		return fmt.Errorf("update CA status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update CA status rows: %w", err)
	}
	if rows == 0 {
		var collecting int
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
			SELECT 1 FROM mesh_imports WHERE ca_id = ? AND status = ?
		)`, id, models.MeshImportStatusCollecting).Scan(&collecting); err != nil {
			return fmt.Errorf("check CA mesh import: %w", err)
		}
		if collecting != 0 {
			return ErrMeshImportInProgress
		}
		return ErrNotFound
	}
	return nil
}

// DeleteCA removes a CA row. ca_id is a plain column on networks, hosts,
// certificates, and blocklist with no DB-level foreign key (it defaults to the
// empty string for pre-multi-CA rows), so referential integrity is enforced
// here: the call refuses while any of those tables still references the CA.
// Without checking all four, deleting a CA orphans rows whose ca_id no longer
// resolves, surfacing later as a silent failure in caForHost (ErrNotFound,
// then 500). Each table is checked independently because they can reference a
// CA in isolation, e.g. a blocklist row whose host was deleted via ON DELETE
// SET NULL, or a host whose ca_id diverged from its network's.
func (s *SQLiteStore) DeleteCA(ctx context.Context, id string) error {
	// BEGIN IMMEDIATE acquires the write lock up front so the reference
	// checks and the DELETE see a consistent snapshot — a concurrent
	// INSERT referencing this CA between the last check and the DELETE
	// would otherwise orphan the child row (#295).
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()
	// Escalate to a write lock immediately.
	if _, err := tx.ExecContext(ctx, `SELECT 1`); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}

	checks := []struct {
		query string
		label string
	}{
		{`SELECT COUNT(1) FROM networks WHERE ca_id = ?`, "network"},
		{`SELECT COUNT(1) FROM hosts WHERE ca_id = ?`, "host"},
		{`SELECT COUNT(1) FROM certificates WHERE ca_id = ?`, "certificate"},
		{`SELECT COUNT(1) FROM blocklist WHERE ca_id = ?`, "blocklist entry"},
	}
	var blockers []string
	for _, c := range checks {
		var n int
		if err := tx.QueryRowContext(ctx, c.query, id).Scan(&n); err != nil {
			return fmt.Errorf("check CA references: %w", err)
		}
		if n > 0 {
			blockers = append(blockers, fmt.Sprintf("%d %s(s)", n, c.label))
		}
	}
	if len(blockers) > 0 {
		return fmt.Errorf("CA still has %s; detach them first", strings.Join(blockers, ", "))
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM cas WHERE id = ?`, id)
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
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete CA: %w", err)
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
