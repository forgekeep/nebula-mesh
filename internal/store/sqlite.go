package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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

	// Enable WAL mode and foreign keys
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("exec %s: %w", pragma, err)
		}
	}

	return &SQLiteStore{db: db}, nil
}

// Migrate applies all pending migrations.
func (s *SQLiteStore) Migrate(_ context.Context) error {
	sqlBytes, err := migrations.FS.ReadFile("001_initial.up.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	if _, err := s.db.Exec(string(sqlBytes)); err != nil {
		return fmt.Errorf("apply migration: %w", err)
	}
	return nil
}

// Close closes the database.
func (s *SQLiteStore) Close() error {
	return s.db.Close()
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
	defer rows.Close()

	var result []*models.Network
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
		query += ` AND groups_json LIKE ?`
		args = append(args, `%"`+filter.Group+`"%`)
	}
	query += ` ORDER BY name`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}
	defer rows.Close()

	var result []*models.Host
	for rows.Next() {
		h, err := s.scanHost(rows)
		if err != nil {
			return nil, fmt.Errorf("scan host: %w", err)
		}
		result = append(result, h)
	}
	return result, rows.Err()
}

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

	rows, _ := result.RowsAffected()
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
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Enrollment Tokens ---

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
	defer tx.Rollback()

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
	defer tx.Rollback()

	// Mark old certs as not current
	_, err = tx.Exec(`UPDATE certificates SET is_current = 0 WHERE host_id = ?`, hostID)
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

	return tx.Commit()
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
	defer rows.Close()

	var result []string
	for rows.Next() {
		var fp string
		if err := rows.Scan(&fp); err != nil {
			return nil, fmt.Errorf("scan fingerprint: %w", err)
		}
		result = append(result, fp)
	}
	return result, rows.Err()
}
