package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store/migrations"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrTokenUsed      = errors.New("token already used")
	ErrTokenExpired   = errors.New("token expired")
	ErrDuplicateEntry = errors.New("duplicate entry")
)

// SQLiteStore implements Store using SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens a SQLite database at the given path.
// Use ":memory:" for in-memory database.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// SQLite ":memory:" creates a per-connection database; restrict the
	// connection pool to a single connection so migrations and subsequent
	// queries hit the same store.
	if dbPath == ":memory:" {
		db.SetMaxOpenConns(1)
	}

	// Enable WAL mode and foreign keys
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			if closeErr := db.Close(); closeErr != nil {
				slog.Error("close db after pragma failure", "error", closeErr)
			}
			return nil, fmt.Errorf("exec %s: %w", pragma, err)
		}
	}

	return &SQLiteStore{db: db}, nil
}

// Migrate applies all pending migrations.
func (s *SQLiteStore) Migrate(_ context.Context) error {
	migrationFiles := []string{
		"001_initial.up.sql",
		"002_config_version.up.sql",
		"003_audit_log.up.sql",
		"004_blocklist_fk.up.sql",
		"005_operators.up.sql",
		"006_operator_totp.up.sql",
	}
	for _, f := range migrationFiles {
		sqlBytes, err := migrations.FS.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", f, err)
		}
		if _, err := s.db.Exec(string(sqlBytes)); err != nil {
			// Ignore "duplicate column" errors for idempotent ALTER TABLE
			if !isDuplicateColumnErr(err) {
				return fmt.Errorf("apply migration %s: %w", f, err)
			}
		}
	}
	return nil
}

func isDuplicateColumnErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate column name")
}

// DB returns the underlying *sql.DB for advanced usage.
func (s *SQLiteStore) DB() *sql.DB {
	return s.db
}

// Close closes the database.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// Ping verifies the database connection is alive.
func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// --- Networks ---

func (s *SQLiteStore) CreateNetwork(_ context.Context, n *models.Network) error {
	_, err := s.db.Exec(
		`INSERT INTO networks (id, name, cidr, created_at) VALUES (?, ?, ?, ?)`,
		n.ID, n.Name, n.CIDR, n.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert network: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetNetwork(_ context.Context, id string) (*models.Network, error) {
	n := &models.Network{}
	err := s.db.QueryRow(
		`SELECT id, name, cidr, created_at FROM networks WHERE id = ?`, id,
	).Scan(&n.ID, &n.Name, &n.CIDR, &n.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}
	return n, nil
}

func (s *SQLiteStore) ListNetworks(_ context.Context) ([]*models.Network, error) {
	rows, err := s.db.Query(`SELECT id, name, cidr, created_at FROM networks ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()

	result := make([]*models.Network, 0)
	for rows.Next() {
		n := &models.Network{}
		if err := rows.Scan(&n.ID, &n.Name, &n.CIDR, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan network: %w", err)
		}
		result = append(result, n)
	}
	return result, rows.Err()
}

// --- Hosts ---

func (s *SQLiteStore) CreateHost(_ context.Context, h *models.Host) error {
	groupsJSON, err := json.Marshal(h.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}

	_, err = s.db.Exec(
		`INSERT INTO hosts (id, network_id, name, nebula_ip, groups_json, role, is_lighthouse, is_relay, public_ip, listen_port, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.NetworkID, h.Name, h.NebulaIP, string(groupsJSON),
		h.Role, h.IsLighthouse, h.IsRelay, h.PublicIP, h.ListenPort,
		h.Status, h.CreatedAt, h.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert host: %w", err)
	}
	return nil
}

func (s *SQLiteStore) scanHost(scanner interface {
	Scan(dest ...any) error
}) (*models.Host, error) {
	h := &models.Host{}
	var groupsJSON string
	var publicIP sql.NullString
	var certFP sql.NullString
	var certExpires sql.NullTime
	var lastSeen sql.NullTime

	err := scanner.Scan(
		&h.ID, &h.NetworkID, &h.Name, &h.NebulaIP, &groupsJSON,
		&h.Role, &h.IsLighthouse, &h.IsRelay, &publicIP, &h.ListenPort,
		&h.Status, &certFP, &certExpires, &lastSeen,
		&h.CreatedAt, &h.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(groupsJSON), &h.Groups); err != nil {
		return nil, fmt.Errorf("unmarshal groups: %w", err)
	}
	if publicIP.Valid {
		h.PublicIP = publicIP.String
	}
	if certFP.Valid {
		h.CertFingerprint = certFP.String
	}
	if certExpires.Valid {
		h.CertExpiresAt = &certExpires.Time
	}
	if lastSeen.Valid {
		h.LastSeenAt = &lastSeen.Time
	}

	return h, nil
}

const hostColumns = `id, network_id, name, nebula_ip, groups_json, role, is_lighthouse, is_relay, public_ip, listen_port, status, cert_fingerprint, cert_expires_at, last_seen_at, created_at, updated_at`

func (s *SQLiteStore) GetHost(_ context.Context, id string) (*models.Host, error) {
	row := s.db.QueryRow(`SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id)
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host: %w", err)
	}
	return h, nil
}

func (s *SQLiteStore) GetHostByFingerprint(_ context.Context, fingerprint string) (*models.Host, error) {
	row := s.db.QueryRow(`SELECT `+hostColumns+` FROM hosts WHERE cert_fingerprint = ?`, fingerprint)
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host by fingerprint: %w", err)
	}
	return h, nil
}

func (s *SQLiteStore) ListHosts(_ context.Context, filter HostFilter) ([]*models.Host, error) {
	query := `SELECT ` + hostColumns + ` FROM hosts WHERE 1=1`
	var args []any

	if filter.NetworkID != "" {
		query += ` AND network_id = ?`
		args = append(args, filter.NetworkID)
	}
	if filter.Status != "" {
		query += ` AND status = ?`
		args = append(args, filter.Status)
	}
	if filter.Group != "" {
		escaped := strings.ReplaceAll(filter.Group, `\`, `\\`)
		escaped = strings.ReplaceAll(escaped, `%`, `\%`)
		escaped = strings.ReplaceAll(escaped, `_`, `\_`)
		query += ` AND groups_json LIKE ? ESCAPE '\'`
		args = append(args, `%"`+escaped+`"%`)
	}
	query += ` ORDER BY name`
	if filter.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, filter.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()

	result := make([]*models.Host, 0)
	for rows.Next() {
		h, err := s.scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		result = append(result, h)
	}
	return result, rows.Err()
}

// UpdateHost persists all host fields.
// NOTE: mutates h.UpdatedAt to current time.
func (s *SQLiteStore) UpdateHost(_ context.Context, h *models.Host) error {
	groupsJSON, err := json.Marshal(h.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}

	h.UpdatedAt = time.Now()
	result, err := s.db.Exec(
		`UPDATE hosts SET name=?, nebula_ip=?, groups_json=?, role=?, is_lighthouse=?, is_relay=?,
		 public_ip=?, listen_port=?, status=?, cert_fingerprint=?, cert_expires_at=?,
		 last_seen_at=?, updated_at=? WHERE id=?`,
		h.Name, h.NebulaIP, string(groupsJSON), h.Role, h.IsLighthouse, h.IsRelay,
		h.PublicIP, h.ListenPort, h.Status, h.CertFingerprint, h.CertExpiresAt,
		h.LastSeenAt, h.UpdatedAt, h.ID,
	)
	if err != nil {
		return fmt.Errorf("update host: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update host rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) UpdateHostLastSeen(_ context.Context, id string, t time.Time) error {
	result, err := s.db.Exec(
		`UPDATE hosts SET last_seen_at=?, updated_at=? WHERE id=?`,
		t, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("update host last seen: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update host last seen rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) UpdateHostCert(_ context.Context, id, fingerprint string, expiresAt time.Time) error {
	result, err := s.db.Exec(
		`UPDATE hosts SET cert_fingerprint=?, cert_expires_at=?, updated_at=? WHERE id=?`,
		fingerprint, expiresAt, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("update host cert: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update host cert rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) UpdateHostStatus(_ context.Context, id string, status models.HostStatus) error {
	result, err := s.db.Exec(
		`UPDATE hosts SET status=?, updated_at=? WHERE id=?`,
		status, time.Now(), id,
	)
	if err != nil {
		return fmt.Errorf("update host status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update host status rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *SQLiteStore) DeleteHost(_ context.Context, id string) error {
	result, err := s.db.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete host rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// BlockHostAndAddToBlocklist atomically blocks a host and adds its cert to the blocklist.
func (s *SQLiteStore) BlockHostAndAddToBlocklist(_ context.Context, id, reason string) (*models.Host, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	row := tx.QueryRow(`SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id)
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host: %w", err)
	}

	if h.CertFingerprint != "" {
		var hostIDVal any = id
		_, err = tx.Exec(
			`INSERT OR REPLACE INTO blocklist (fingerprint, host_id, reason, created_at) VALUES (?, ?, ?, ?)`,
			h.CertFingerprint, hostIDVal, reason, time.Now(),
		)
		if err != nil {
			return nil, fmt.Errorf("add to blocklist: %w", err)
		}
	}

	result, err := tx.Exec(
		`UPDATE hosts SET status=?, updated_at=? WHERE id=?`,
		models.HostStatusBlocked, time.Now(), id,
	)
	if err != nil {
		return nil, fmt.Errorf("update host status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("update host status rows affected: %w", err)
	}
	if rows == 0 {
		return nil, ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit block host: %w", err)
	}

	h.Status = models.HostStatusBlocked
	return h, nil
}

// UnblockHostAndRemoveFromBlocklist atomically marks a blocked host as pending
// and removes its certificate fingerprint from the blocklist. The host must
// re-enroll to obtain a new certificate after unblocking.
func (s *SQLiteStore) UnblockHostAndRemoveFromBlocklist(_ context.Context, id string) (*models.Host, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	row := tx.QueryRow(`SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id)
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host: %w", err)
	}

	if h.CertFingerprint != "" {
		if _, err := tx.Exec(`DELETE FROM blocklist WHERE fingerprint = ?`, h.CertFingerprint); err != nil {
			return nil, fmt.Errorf("remove from blocklist: %w", err)
		}
	}

	result, err := tx.Exec(
		`UPDATE hosts SET status=?, updated_at=? WHERE id=?`,
		models.HostStatusPending, time.Now(), id,
	)
	if err != nil {
		return nil, fmt.Errorf("update host status: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("update host status rows affected: %w", err)
	}
	if rows == 0 {
		return nil, ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit unblock host: %w", err)
	}

	h.Status = models.HostStatusPending
	return h, nil
}

// DeleteHostAndBlockCert atomically deletes a host and adds its cert to the blocklist.
func (s *SQLiteStore) DeleteHostAndBlockCert(_ context.Context, id, reason string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	row := tx.QueryRow(`SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id)
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get host: %w", err)
	}

	if h.CertFingerprint != "" {
		var hostIDVal any = id
		_, err = tx.Exec(
			`INSERT OR REPLACE INTO blocklist (fingerprint, host_id, reason, created_at) VALUES (?, ?, ?, ?)`,
			h.CertFingerprint, hostIDVal, reason, time.Now(),
		)
		if err != nil {
			return fmt.Errorf("add to blocklist: %w", err)
		}
	}

	result, err := tx.Exec(`DELETE FROM hosts WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete host: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete host rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete host: %w", err)
	}
	return nil
}

// --- Enrollment Tokens ---

// CreateHostAndToken atomically creates a host and its enrollment token.
func (s *SQLiteStore) CreateHostAndToken(_ context.Context, h *models.Host, t *models.EnrollmentToken) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	groupsJSON, err := json.Marshal(h.Groups)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}

	_, err = tx.Exec(
		`INSERT INTO hosts (id, network_id, name, nebula_ip, groups_json, role, is_lighthouse, is_relay, public_ip, listen_port, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.NetworkID, h.Name, h.NebulaIP, string(groupsJSON),
		h.Role, h.IsLighthouse, h.IsRelay, h.PublicIP, h.ListenPort,
		h.Status, h.CreatedAt, h.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert host: %w", err)
	}

	_, err = tx.Exec(
		`INSERT INTO enrollment_tokens (id, host_id, token, used, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.HostID, t.Token, false, t.ExpiresAt, t.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit create host and token: %w", err)
	}
	return nil
}

func (s *SQLiteStore) CreateToken(_ context.Context, t *models.EnrollmentToken) error {
	_, err := s.db.Exec(
		`INSERT INTO enrollment_tokens (id, host_id, token, used, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.HostID, t.Token, false, t.ExpiresAt, t.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ConsumeToken(_ context.Context, token string) (*models.EnrollmentToken, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	t := &models.EnrollmentToken{}
	err = tx.QueryRow(
		`SELECT id, host_id, token, used, expires_at, created_at FROM enrollment_tokens WHERE token = ?`,
		token,
	).Scan(&t.ID, &t.HostID, &t.Token, &t.Used, &t.ExpiresAt, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}

	if t.Used {
		return nil, ErrTokenUsed
	}
	if time.Now().After(t.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	now := time.Now()
	_, err = tx.Exec(`UPDATE enrollment_tokens SET used = 1, used_at = ? WHERE id = ?`, now, t.ID)
	if err != nil {
		return nil, fmt.Errorf("consume token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}

	t.Used = true
	t.UsedAt = &now
	return t, nil
}

// --- Certificates ---

func (s *SQLiteStore) SaveCertificate(_ context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	if err := s.saveCertificateInTx(tx, hostID, fp, certPEM, notBefore, notAfter); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit save certificate: %w", err)
	}
	return nil
}

// SaveCertificateAndEnrollHost atomically saves a certificate and marks the host as enrolled.
func (s *SQLiteStore) SaveCertificateAndEnrollHost(_ context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	if err := s.saveCertificateInTx(tx, hostID, fp, certPEM, notBefore, notAfter); err != nil {
		return err
	}

	// Update host: status=enrolled, cert_fingerprint, cert_expires_at
	result, err := tx.Exec(
		`UPDATE hosts SET status=?, cert_fingerprint=?, cert_expires_at=?, updated_at=? WHERE id=?`,
		models.HostStatusEnrolled, fp, notAfter, time.Now(), hostID,
	)
	if err != nil {
		return fmt.Errorf("update host: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update host rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enroll host: %w", err)
	}
	return nil
}

// SaveCertificateAndUpdateHostCert atomically saves a certificate and updates the host's cert metadata.
func (s *SQLiteStore) SaveCertificateAndUpdateHostCert(_ context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	if err := s.saveCertificateInTx(tx, hostID, fp, certPEM, notBefore, notAfter); err != nil {
		return err
	}

	// Update host cert metadata only
	result, err := tx.Exec(
		`UPDATE hosts SET cert_fingerprint=?, cert_expires_at=?, updated_at=? WHERE id=?`,
		fp, notAfter, time.Now(), hostID,
	)
	if err != nil {
		return fmt.Errorf("update host cert: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update host cert rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit update host cert: %w", err)
	}
	return nil
}

// saveCertificateInTx saves a certificate within an existing transaction.
func (s *SQLiteStore) saveCertificateInTx(tx *sql.Tx, hostID, fp string, certPEM []byte, notBefore, notAfter time.Time) error {
	_, err := tx.Exec(`UPDATE certificates SET is_current = 0 WHERE host_id = ?`, hostID)
	if err != nil {
		return fmt.Errorf("unmark current: %w", err)
	}

	prefix := hostID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	id := fmt.Sprintf("cert_%s_%d", prefix, time.Now().UnixNano())
	_, err = tx.Exec(
		`INSERT INTO certificates (id, host_id, fingerprint, pem, not_before, not_after, is_current, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, 1, ?)`,
		id, hostID, fp, string(certPEM), notBefore, notAfter, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("insert certificate: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetCurrentCertificate(_ context.Context, hostID string) ([]byte, error) {
	var pem string
	err := s.db.QueryRow(
		`SELECT pem FROM certificates WHERE host_id = ? AND is_current = 1`, hostID,
	).Scan(&pem)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get certificate: %w", err)
	}
	return []byte(pem), nil
}

func (s *SQLiteStore) GetCertificateInfo(_ context.Context, hostID string) (*models.CertificateInfo, error) {
	ci := &models.CertificateInfo{}
	err := s.db.QueryRow(
		`SELECT id, host_id, fingerprint, pem, not_before, not_after, is_current, created_at
		 FROM certificates WHERE host_id = ? AND is_current = 1`, hostID,
	).Scan(&ci.ID, &ci.HostID, &ci.Fingerprint, &ci.PEM, &ci.NotBefore, &ci.NotAfter, &ci.IsCurrent, &ci.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get cert info: %w", err)
	}
	return ci, nil
}

func (s *SQLiteStore) ListEnrolledHostCerts(_ context.Context) ([]*models.CertificateInfo, error) {
	rows, err := s.db.Query(
		`SELECT c.id, c.host_id, c.fingerprint, c.pem, c.not_before, c.not_after, c.is_current, c.created_at
		 FROM certificates c
		 JOIN hosts h ON h.id = c.host_id
		 WHERE c.is_current = 1 AND h.status = 'enrolled'`)
	if err != nil {
		return nil, fmt.Errorf("list enrolled certs: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()

	result := make([]*models.CertificateInfo, 0)
	for rows.Next() {
		ci := &models.CertificateInfo{}
		if err := rows.Scan(&ci.ID, &ci.HostID, &ci.Fingerprint, &ci.PEM, &ci.NotBefore, &ci.NotAfter, &ci.IsCurrent, &ci.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan cert: %w", err)
		}
		result = append(result, ci)
	}
	return result, rows.Err()
}

// --- Blocklist ---

func (s *SQLiteStore) AddToBlocklist(_ context.Context, fingerprint, hostID, reason string) error {
	var hostIDVal any
	if hostID != "" {
		hostIDVal = hostID
	}
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO blocklist (fingerprint, host_id, reason, created_at) VALUES (?, ?, ?, ?)`,
		fingerprint, hostIDVal, reason, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("add to blocklist: %w", err)
	}
	return nil
}

func (s *SQLiteStore) RemoveFromBlocklist(_ context.Context, fingerprint string) error {
	_, err := s.db.Exec(`DELETE FROM blocklist WHERE fingerprint = ?`, fingerprint)
	if err != nil {
		return fmt.Errorf("remove from blocklist: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetBlocklist(_ context.Context) ([]string, error) {
	rows, err := s.db.Query(`SELECT fingerprint FROM blocklist ORDER BY fingerprint`)
	if err != nil {
		return nil, fmt.Errorf("get blocklist: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()

	result := make([]string, 0)
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("scan fingerprint: %w", err)
		}
		result = append(result, fp)
	}
	return result, rows.Err()
}

// --- Config Versioning ---

func (s *SQLiteStore) BumpNetworkConfigVersion(_ context.Context, networkID string) error {
	_, err := s.db.Exec(`UPDATE networks SET config_version = config_version + 1 WHERE id = ?`, networkID)
	if err != nil {
		return fmt.Errorf("bump config version: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetNetworkConfigVersion(_ context.Context, networkID string) (int, error) {
	var version int
	err := s.db.QueryRow(`SELECT config_version FROM networks WHERE id = ?`, networkID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("get config version: %w", err)
	}
	return version, nil
}

// --- Network Config ---

func (s *SQLiteStore) GetNetworkConfig(_ context.Context, networkID, key string) (string, error) {
	var value string
	err := s.db.QueryRow(
		`SELECT value FROM network_config WHERE network_id = ? AND key = ?`, networkID, key,
	).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get network config: %w", err)
	}
	return value, nil
}

func (s *SQLiteStore) SetNetworkConfig(_ context.Context, networkID, key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO network_config (network_id, key, value) VALUES (?, ?, ?)
		 ON CONFLICT(network_id, key) DO UPDATE SET value = excluded.value`,
		networkID, key, value,
	)
	if err != nil {
		return fmt.Errorf("set network config: %w", err)
	}
	return nil
}

// SetNetworkConfigAndBumpVersion atomically sets a config value and bumps the config version.
func (s *SQLiteStore) SetNetworkConfigAndBumpVersion(_ context.Context, networkID, key, value string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	_, err = tx.Exec(
		`INSERT INTO network_config (network_id, key, value) VALUES (?, ?, ?)
		 ON CONFLICT(network_id, key) DO UPDATE SET value = excluded.value`,
		networkID, key, value,
	)
	if err != nil {
		return fmt.Errorf("set network config: %w", err)
	}

	_, err = tx.Exec(`UPDATE networks SET config_version = config_version + 1 WHERE id = ?`, networkID)
	if err != nil {
		return fmt.Errorf("bump config version: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit config and version: %w", err)
	}
	return nil
}

// --- Audit Log ---

func (s *SQLiteStore) AddAuditEntry(_ context.Context, actor, action, resource, details string) error {
	id := fmt.Sprintf("audit_%d", time.Now().UnixNano())
	_, err := s.db.Exec(
		`INSERT INTO audit_log (id, actor, action, resource, details) VALUES (?, ?, ?, ?, ?)`,
		id, actor, action, resource, details,
	)
	if err != nil {
		return fmt.Errorf("add audit entry: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListAuditEntries(_ context.Context, filter AuditFilter) ([]*models.AuditEntry, error) {
	query := `SELECT id, timestamp, actor, action, resource, COALESCE(details, '') FROM audit_log WHERE 1=1`
	var args []any

	if filter.Action != "" {
		query += ` AND action = ?`
		args = append(args, filter.Action)
	}
	query += ` ORDER BY timestamp DESC`

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	query += ` LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit entries: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()

	result := make([]*models.AuditEntry, 0)
	for rows.Next() {
		e := &models.AuditEntry{}
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Actor, &e.Action, &e.Resource, &e.Details); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		result = append(result, e)
	}
	return result, rows.Err()
}
