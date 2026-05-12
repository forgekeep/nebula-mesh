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

const caColumns = `id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, created_at, updated_at`

func scanCA(scanner interface {
	Scan(dest ...any) error
}) (*models.CA, error) {
	var c models.CA
	if err := scanner.Scan(
		&c.ID, &c.Name, &c.OwnerOperatorID, &c.CertPEM, &c.Fingerprint,
		&c.NotBefore, &c.NotAfter, &c.Status,
		&c.EncryptedKeyDEK, &c.NonceDEK,
		&c.EncryptedKeyMaterial, &c.NonceKey,
		&c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *SQLiteStore) CreateCA(_ context.Context, c *models.CA) error {
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
	_, err := s.db.Exec(
		`INSERT INTO cas (`+caColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.OwnerOperatorID, c.CertPEM, c.Fingerprint,
		c.NotBefore, c.NotAfter, c.Status,
		c.EncryptedKeyDEK, c.NonceDEK,
		c.EncryptedKeyMaterial, c.NonceKey,
		c.CreatedAt, c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert CA: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetCA(_ context.Context, id string) (*models.CA, error) {
	row := s.db.QueryRow(`SELECT `+caColumns+` FROM cas WHERE id = ?`, id)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get CA: %w", err)
	}
	return c, nil
}

func (s *SQLiteStore) GetCAByFingerprint(_ context.Context, fp string) (*models.CA, error) {
	row := s.db.QueryRow(`SELECT `+caColumns+` FROM cas WHERE fingerprint = ?`, fp)
	c, err := scanCA(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get CA by fingerprint: %w", err)
	}
	return c, nil
}

func (s *SQLiteStore) ListCAs(_ context.Context) ([]*models.CA, error) {
	rows, err := s.db.Query(`SELECT ` + caColumns + ` FROM cas ORDER BY name`)
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

func (s *SQLiteStore) ListCAsByOwner(_ context.Context, ownerID string) ([]*models.CA, error) {
	rows, err := s.db.Query(`SELECT `+caColumns+` FROM cas WHERE owner_operator_id = ? ORDER BY name`, ownerID)
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

func (s *SQLiteStore) UpdateCAStatus(_ context.Context, id string, status models.CAStatus) error {
	result, err := s.db.Exec(`UPDATE cas SET status=?, updated_at=? WHERE id=?`, status, time.Now(), id)
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

// BackfillCAID stamps ca_id on every existing row in networks / hosts /
// certificates / blocklist that still has an empty ca_id. Used once after
// the legacy CA is imported into the cas table.
func (s *SQLiteStore) BackfillCAID(_ context.Context, caID string) error {
	if caID == "" {
		return fmt.Errorf("caID is required")
	}
	for _, table := range []string{"networks", "hosts", "certificates", "blocklist"} {
		stmt := `UPDATE ` + table + ` SET ca_id = ? WHERE ca_id = ''`
		if _, err := s.db.Exec(stmt, caID); err != nil {
			return fmt.Errorf("backfill ca_id on %s: %w", table, err)
		}
	}
	return nil
}

// DeleteCA removes a CA row. The DB-level ON DELETE RESTRICT on
// networks.ca_id (when enforced by application logic) is mirrored here:
// the call returns an error if networks still reference the CA, so the
// operator must retire / move networks first.
func (s *SQLiteStore) DeleteCA(ctx context.Context, id string) error {
	row := s.db.QueryRow(`SELECT COUNT(1) FROM networks WHERE ca_id = ?`, id)
	var n int
	if err := row.Scan(&n); err != nil {
		return fmt.Errorf("check CA references: %w", err)
	}
	if n > 0 {
		return fmt.Errorf("CA still has %d network(s); detach them first", n)
	}
	result, err := s.db.Exec(`DELETE FROM cas WHERE id = ?`, id)
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
