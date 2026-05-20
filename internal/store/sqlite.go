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
	ErrNotFound            = errors.New("not found")
	ErrTokenUsed           = errors.New("token already used")
	ErrTokenExpired        = errors.New("token expired")
	ErrDuplicateEntry      = errors.New("duplicate entry")
	ErrRekeyAlreadyPending = errors.New("rekey already pending")
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

// Migrate applies all pending migrations. Each migration file is executed
// at most once per database — its name is recorded in `schema_migrations`
// once applied. This fixes two latent issues:
//
//   - Destructive recreate-style migrations (e.g. 004_blocklist_fk, which
//     rebuilds `blocklist` via blocklist_new + RENAME) used to run on every
//     start, silently dropping columns that later migrations had added.
//   - Multi-statement migration files used to be Exec'd as one string;
//     `modernc.org/sqlite` stops processing the remainder of the blob on
//     the first error (e.g. a duplicate-column ALTER), so the trailing
//     statements were skipped. We now split each file by top-level `;`
//     boundaries and Exec one statement at a time.
//
// See https://github.com/juev/nebula-mesh/issues/37.
func (s *SQLiteStore) Migrate(_ context.Context) error {
	migrationFiles := []string{
		"001_initial.up.sql",
		"002_config_version.up.sql",
		"003_audit_log.up.sql",
		"004_blocklist_fk.up.sql",
		"005_operators.up.sql",
		"006_operator_totp.up.sql",
		"007_operator_oidc.up.sql",
		"008_host_advanced.up.sql",
		"009_per_operator_cas.up.sql",
		"010_cert_alerts.up.sql",
		"011_server_settings.up.sql",
		"012_agent_auth.up.sql",
		"013_host_mobile.up.sql",
		"014_multi_address.up.sql",
		"015_ca_predecessor.up.sql",
		"016_enrollment_token_hash.up.sql",
	}

	// Tracking table. Created once; idempotent on subsequent starts.
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		name        TEXT PRIMARY KEY,
		applied_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	for _, f := range migrationFiles {
		applied, err := s.migrationApplied(f)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", f, err)
		}
		if applied {
			continue
		}
		sqlBytes, err := migrations.FS.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", f, err)
		}
		for _, stmt := range splitSQLStatements(string(sqlBytes)) {
			if _, err := s.db.Exec(stmt); err != nil {
				if isDuplicateColumnErr(err) {
					// Tolerated for backward compatibility with DBs that
					// partially applied a buggy earlier version of this
					// migration loader.
					continue
				}
				return fmt.Errorf("apply migration %s stmt %q: %w", f, firstLine(stmt), err)
			}
		}
		if _, err := s.db.Exec(`INSERT OR REPLACE INTO schema_migrations(name) VALUES (?)`, f); err != nil {
			return fmt.Errorf("record migration %s: %w", f, err)
		}
	}

	// Repair path for databases that applied the broken pre-#37 loader:
	// `blocklist` may be missing the `ca_id` column even though every
	// migration is now flagged as applied. Re-run the affected ALTER
	// outside the normal migration flow so existing installs heal on the
	// next start.
	if err := s.repairBlocklistCAID(); err != nil {
		return fmt.Errorf("repair blocklist ca_id: %w", err)
	}
	return nil
}

func (s *SQLiteStore) migrationApplied(name string) (bool, error) {
	var got string
	row := s.db.QueryRow(`SELECT name FROM schema_migrations WHERE name = ?`, name)
	if err := row.Scan(&got); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return got == name, nil
}

// repairBlocklistCAID heals databases that ran the buggy multi-statement
// migration loader before issue #37 was fixed. If `blocklist.ca_id` is
// absent, add it (together with its index) so multi-CA logic works.
func (s *SQLiteStore) repairBlocklistCAID() error {
	row := s.db.QueryRow(`SELECT COUNT(1) FROM pragma_table_info('blocklist') WHERE name = 'ca_id'`)
	var n int
	if err := row.Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	if _, err := s.db.Exec(`ALTER TABLE blocklist ADD COLUMN ca_id TEXT NOT NULL DEFAULT ''`); err != nil {
		if !isDuplicateColumnErr(err) {
			return err
		}
	}
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_blocklist_ca ON blocklist(ca_id)`); err != nil {
		return err
	}
	return nil
}

// splitSQLStatements splits a SQL script on top-level `;` boundaries. It
// understands single- and double-quoted strings and `--` line comments,
// which is enough for the migration files we ship (no nested BEGIN/END or
// string-quoted semicolons elsewhere). Empty trailing statements are
// dropped.
func splitSQLStatements(src string) []string {
	var (
		out      []string
		current  []byte
		inSingle bool
		inDouble bool
		inLine   bool
		paren    int
	)
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inLine {
			current = append(current, c)
			if c == '\n' {
				inLine = false
			}
			continue
		}
		switch {
		case !inSingle && !inDouble && c == '-' && i+1 < len(src) && src[i+1] == '-':
			inLine = true
			current = append(current, c)
		case !inDouble && c == '\'':
			inSingle = !inSingle
			current = append(current, c)
		case !inSingle && c == '"':
			inDouble = !inDouble
			current = append(current, c)
		case !inSingle && !inDouble && c == '(':
			paren++
			current = append(current, c)
		case !inSingle && !inDouble && c == ')':
			if paren > 0 {
				paren--
			}
			current = append(current, c)
		case !inSingle && !inDouble && paren == 0 && c == ';':
			stmt := strings.TrimSpace(string(current))
			if stmt != "" {
				out = append(out, stmt)
			}
			current = current[:0]
		default:
			current = append(current, c)
		}
	}
	if tail := strings.TrimSpace(string(current)); tail != "" {
		out = append(out, tail)
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
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

// setNetworkCIDRs replaces all CIDRs for a network in a transaction.
// Deletes existing rows and inserts new ones with position-based ordering.
func (s *SQLiteStore) setNetworkCIDRs(ctx context.Context, tx *sql.Tx, networkID string, cidrs []string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM network_cidrs WHERE network_id = ?", networkID); err != nil {
		return fmt.Errorf("delete network cidrs: %w", err)
	}

	for position, cidr := range cidrs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO network_cidrs (network_id, position, cidr) VALUES (?, ?, ?)`,
			networkID, position, cidr,
		); err != nil {
			return fmt.Errorf("insert network cidr at position %d: %w", position, err)
		}
	}
	return nil
}

// loadNetworkCIDRs retrieves all CIDRs for a network in order.
func (s *SQLiteStore) loadNetworkCIDRs(ctx context.Context, networkID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT cidr FROM network_cidrs WHERE network_id = ? ORDER BY position`,
		networkID,
	)
	if err != nil {
		return nil, fmt.Errorf("query network cidrs: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()

	var cidrs []string
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			return nil, fmt.Errorf("scan cidr: %w", err)
		}
		cidrs = append(cidrs, cidr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cidrs: %w", err)
	}

	// Return empty slice instead of nil for consistency
	if cidrs == nil {
		cidrs = make([]string, 0)
	}
	return cidrs, nil
}

func (s *SQLiteStore) CreateNetwork(ctx context.Context, n *models.Network) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO networks (id, name, created_at, ca_id) VALUES (?, ?, ?, ?)`,
		n.ID, n.Name, n.CreatedAt, n.CAID,
	); err != nil {
		return fmt.Errorf("insert network: %w", err)
	}

	if err := s.setNetworkCIDRs(ctx, tx, n.ID, n.CIDRs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *SQLiteStore) UpdateNetwork(ctx context.Context, n *models.Network) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	result, err := tx.ExecContext(ctx,
		`UPDATE networks SET name = ?, ca_id = ? WHERE id = ?`,
		n.Name, n.CAID, n.ID,
	)
	if err != nil {
		return fmt.Errorf("update network: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}

	if err := s.setNetworkCIDRs(ctx, tx, n.ID, n.CIDRs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetNetwork(ctx context.Context, id string) (*models.Network, error) {
	n := &models.Network{}
	err := s.db.QueryRow(
		`SELECT id, name, created_at, ca_id FROM networks WHERE id = ?`, id,
	).Scan(&n.ID, &n.Name, &n.CreatedAt, &n.CAID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}

	cidrs, err := s.loadNetworkCIDRs(ctx, n.ID)
	if err != nil {
		return nil, err
	}
	n.CIDRs = cidrs

	return n, nil
}

func (s *SQLiteStore) ListNetworks(ctx context.Context) ([]*models.Network, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_at, ca_id FROM networks ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list networks: %w", err)
	}

	// Scan all networks first before querying for CIDRs.
	// This avoids nested queries on SQLite which can cause deadlocks.
	result := make([]*models.Network, 0)
	for rows.Next() {
		n := &models.Network{}
		if err := rows.Scan(&n.ID, &n.Name, &n.CreatedAt, &n.CAID); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan network: %w", err)
		}
		result = append(result, n)
	}
	_ = rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load CIDRs for each network after closing the rows.
	for _, n := range result {
		cidrs, err := s.loadNetworkCIDRs(ctx, n.ID)
		if err != nil {
			return nil, err
		}
		n.CIDRs = cidrs
	}

	return result, nil
}

// --- Hosts ---

// setHostAddresses replaces all addresses for a host in a transaction.
// Deletes existing rows and inserts new ones with position-based ordering.
func (s *SQLiteStore) setHostAddresses(ctx context.Context, tx *sql.Tx, hostID string, addrs []string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM host_addresses WHERE host_id = ?", hostID); err != nil {
		return fmt.Errorf("delete host addresses: %w", err)
	}

	for position, addr := range addrs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`,
			hostID, position, addr,
		); err != nil {
			return fmt.Errorf("insert host address at position %d: %w", position, err)
		}
	}
	return nil
}

// loadHostAddresses retrieves all addresses for a host in order.
func (s *SQLiteStore) loadHostAddresses(ctx context.Context, hostID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT address FROM host_addresses WHERE host_id = ? ORDER BY position`,
		hostID,
	)
	if err != nil {
		return nil, fmt.Errorf("query host addresses: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			slog.Error("close rows", "error", err)
		}
	}()

	var addrs []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, fmt.Errorf("scan address: %w", err)
		}
		addrs = append(addrs, addr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate addresses: %w", err)
	}

	// Return empty slice instead of nil for consistency
	if addrs == nil {
		addrs = make([]string, 0)
	}
	return addrs, nil
}

func (s *SQLiteStore) CreateHost(ctx context.Context, h *models.Host) error {
	tx, err := s.db.BeginTx(ctx, nil)
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
	advancedJSON, err := marshalAdvanced(h.Advanced)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO hosts (id, network_id, name, groups_json, role, is_lighthouse, is_relay, public_ip, listen_port, status, created_at, updated_at, advanced_json, ca_id, kind, variant)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.NetworkID, h.Name, string(groupsJSON),
		h.Role, h.IsLighthouse, h.IsRelay, h.PublicIP, h.ListenPort,
		h.Status, h.CreatedAt, h.UpdatedAt, advancedJSON, h.CAID,
		string(h.Kind), string(h.Variant),
	); err != nil {
		return fmt.Errorf("insert host: %w", err)
	}

	if err := s.setHostAddresses(ctx, tx, h.ID, h.NebulaIPs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

func marshalAdvanced(adv *models.HostAdvanced) (string, error) {
	if adv == nil {
		return "", nil
	}
	b, err := json.Marshal(adv)
	if err != nil {
		return "", fmt.Errorf("marshal advanced: %w", err)
	}
	return string(b), nil
}

func (s *SQLiteStore) scanHost(scanner interface {
	Scan(dest ...any) error
}) (*models.Host, error) {
	h := &models.Host{}
	var groupsJSON string
	var advancedJSON string
	var publicIP sql.NullString
	var certFP sql.NullString
	var prevCertFP sql.NullString
	var certExpires sql.NullTime
	var certRotatedAt sql.NullTime
	var lastSeen sql.NullTime
	var signingPub sql.NullString
	var kind string
	var variant string

	err := scanner.Scan(
		&h.ID, &h.NetworkID, &h.Name, &groupsJSON,
		&h.Role, &h.IsLighthouse, &h.IsRelay, &publicIP, &h.ListenPort,
		&h.Status, &certFP, &certExpires, &lastSeen,
		&h.CreatedAt, &h.UpdatedAt, &advancedJSON, &h.CAID,
		&prevCertFP, &certRotatedAt, &h.PendingRekey, &signingPub, &kind, &variant,
	)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(groupsJSON), &h.Groups); err != nil {
		return nil, fmt.Errorf("unmarshal groups: %w", err)
	}
	if advancedJSON != "" {
		var adv models.HostAdvanced
		if err := json.Unmarshal([]byte(advancedJSON), &adv); err != nil {
			return nil, fmt.Errorf("unmarshal advanced: %w", err)
		}
		h.Advanced = &adv
	}
	if publicIP.Valid {
		h.PublicIP = publicIP.String
	}
	if certFP.Valid {
		h.CertFingerprint = certFP.String
	}
	if prevCertFP.Valid {
		h.PrevCertFingerprint = prevCertFP.String
	}
	if certExpires.Valid {
		h.CertExpiresAt = &certExpires.Time
	}
	if certRotatedAt.Valid {
		h.CertRotatedAt = &certRotatedAt.Time
	}
	if lastSeen.Valid {
		h.LastSeenAt = &lastSeen.Time
	}
	if signingPub.Valid {
		h.SigningPubPEM = signingPub.String
	}
	h.Kind = models.HostKind(kind)
	h.Variant = models.HostVariant(variant)

	return h, nil
}

const hostColumns = `id, network_id, name, groups_json, role, is_lighthouse, is_relay, public_ip, listen_port, status, cert_fingerprint, cert_expires_at, last_seen_at, created_at, updated_at, advanced_json, ca_id, prev_cert_fingerprint, cert_rotated_at, pending_rekey, signing_pub_pem, kind, variant`

func (s *SQLiteStore) GetHost(ctx context.Context, id string) (*models.Host, error) {
	row := s.db.QueryRow(`SELECT `+hostColumns+` FROM hosts WHERE id = ?`, id)
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host: %w", err)
	}

	addrs, err := s.loadHostAddresses(ctx, h.ID)
	if err != nil {
		return nil, err
	}
	h.NebulaIPs = addrs

	return h, nil
}

// GetHostByFingerprint resolves the host by either its current or previous
// cert fingerprint. The previous-fingerprint match window exists so cert
// auto-rotation does not lock the agent out between server-side cert update
// and on-disk cert write (ADR 0004 §7.1 cert rotation overlap).
//
// The returned host's CertFingerprint always reflects the row's current
// value; callers that need to know which fingerprint matched can compare
// against the input.
func (s *SQLiteStore) GetHostByFingerprint(ctx context.Context, fingerprint string) (*models.Host, error) {
	row := s.db.QueryRow(
		`SELECT `+hostColumns+` FROM hosts WHERE cert_fingerprint = ? OR prev_cert_fingerprint = ?`,
		fingerprint, fingerprint,
	)
	h, err := s.scanHost(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get host by fingerprint: %w", err)
	}

	addrs, err := s.loadHostAddresses(ctx, h.ID)
	if err != nil {
		return nil, err
	}
	h.NebulaIPs = addrs

	return h, nil
}

func (s *SQLiteStore) ListHosts(ctx context.Context, filter HostFilter) ([]*models.Host, error) {
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

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}

	// Scan all hosts first before querying for addresses.
	// This avoids nested queries on SQLite which can cause deadlocks.
	result := make([]*models.Host, 0)
	for rows.Next() {
		h, err := s.scanHost(rows)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan host: %w", err)
		}
		result = append(result, h)
	}
	_ = rows.Close()

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load addresses for each host after closing the rows.
	for _, h := range result {
		addrs, err := s.loadHostAddresses(ctx, h.ID)
		if err != nil {
			return nil, err
		}
		h.NebulaIPs = addrs
	}

	return result, nil
}

// UpdateHost persists all host fields.
// NOTE: mutates h.UpdatedAt to current time.
func (s *SQLiteStore) UpdateHost(ctx context.Context, h *models.Host) error {
	tx, err := s.db.BeginTx(ctx, nil)
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

	advancedJSON, err := marshalAdvanced(h.Advanced)
	if err != nil {
		return err
	}
	h.UpdatedAt = time.Now()
	result, err := tx.ExecContext(ctx,
		`UPDATE hosts SET name=?, groups_json=?, role=?, is_lighthouse=?, is_relay=?,
		 public_ip=?, listen_port=?, status=?, cert_fingerprint=?, cert_expires_at=?,
		 last_seen_at=?, updated_at=?, advanced_json=?, kind=?, variant=?, pending_rekey=? WHERE id=?`,
		h.Name, string(groupsJSON), h.Role, h.IsLighthouse, h.IsRelay,
		h.PublicIP, h.ListenPort, h.Status, h.CertFingerprint, h.CertExpiresAt,
		h.LastSeenAt, h.UpdatedAt, advancedJSON, string(h.Kind), string(h.Variant), h.PendingRekey, h.ID,
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

	if err := s.setHostAddresses(ctx, tx, h.ID, h.NebulaIPs); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
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
// If the blocked host was an enrolled lighthouse, the network's config_version is
// bumped so peers stop directing traffic at it on their next poll.
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

	wasEnrolledLighthouse := h.IsLighthouse && h.Status == models.HostStatusEnrolled

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

	if wasEnrolledLighthouse {
		if _, err := tx.Exec(
			`UPDATE networks SET config_version = config_version + 1 WHERE id = ?`,
			h.NetworkID,
		); err != nil {
			return nil, fmt.Errorf("bump config version: %w", err)
		}
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
// If the deleted host was an enrolled lighthouse, the network's config_version is
// bumped so peers stop directing traffic at it on their next poll.
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

	wasEnrolledLighthouse := h.IsLighthouse && h.Status == models.HostStatusEnrolled

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

	if wasEnrolledLighthouse {
		if _, err := tx.Exec(
			`UPDATE networks SET config_version = config_version + 1 WHERE id = ?`,
			h.NetworkID,
		); err != nil {
			return fmt.Errorf("bump config version: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit delete host: %w", err)
	}
	return nil
}

// --- Agent authorization (ADR 0004) ---

// SetPrevFingerprint records the previous cert fingerprint and the rotation
// timestamp on the host row. Called from SaveCertificateAndUpdateHostCert
// before the new fingerprint is written so the overlap window is preserved.
func (s *SQLiteStore) SetPrevFingerprint(_ context.Context, hostID, prev string, rotatedAt time.Time) error {
	res, err := s.db.Exec(
		`UPDATE hosts SET prev_cert_fingerprint = ?, cert_rotated_at = ?, updated_at = ? WHERE id = ?`,
		prev, rotatedAt, time.Now(), hostID,
	)
	if err != nil {
		return fmt.Errorf("set prev fingerprint: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set prev fingerprint rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearPrevFingerprint drops the rotation overlap state once the agent has
// successfully polled under the new fingerprint or the wall-clock window
// expired.
func (s *SQLiteStore) ClearPrevFingerprint(_ context.Context, hostID string) error {
	res, err := s.db.Exec(
		`UPDATE hosts SET prev_cert_fingerprint = NULL, cert_rotated_at = NULL, updated_at = ? WHERE id = ?`,
		time.Now(), hostID,
	)
	if err != nil {
		return fmt.Errorf("clear prev fingerprint: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("clear prev fingerprint rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetPendingRekey flips the pending_rekey flag atomically. If the flag is
// already set on this host the call returns ErrRekeyAlreadyPending so a
// duplicate force-rotate request can be rejected with 409.
func (s *SQLiteStore) SetPendingRekey(_ context.Context, hostID string) error {
	res, err := s.db.Exec(
		`UPDATE hosts SET pending_rekey = 1, updated_at = ? WHERE id = ? AND pending_rekey = 0`,
		time.Now(), hostID,
	)
	if err != nil {
		return fmt.Errorf("set pending rekey: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set pending rekey rows affected: %w", err)
	}
	if n == 0 {
		// Either the host does not exist or pending_rekey is already 1.
		// Distinguish by re-reading the row.
		var exists int
		row := s.db.QueryRow(`SELECT 1 FROM hosts WHERE id = ?`, hostID)
		if err := row.Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("scan host existence: %w", err)
		}
		return ErrRekeyAlreadyPending
	}
	return nil
}

// ClearPendingRekey resets the pending_rekey flag, typically after the agent
// has redeemed the rekey token and the new keypair has been bound to the
// existing host row.
func (s *SQLiteStore) ClearPendingRekey(_ context.Context, hostID string) error {
	res, err := s.db.Exec(
		`UPDATE hosts SET pending_rekey = 0, updated_at = ? WHERE id = ?`,
		time.Now(), hostID,
	)
	if err != nil {
		return fmt.Errorf("clear pending rekey: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("clear pending rekey rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateHostSigningPub stores the Ed25519 PEM public key bound to the host's
// signing identity at enrollment / re-enrollment time.
func (s *SQLiteStore) UpdateHostSigningPub(_ context.Context, hostID, signingPubPEM string) error {
	res, err := s.db.Exec(
		`UPDATE hosts SET signing_pub_pem = ?, updated_at = ? WHERE id = ?`,
		signingPubPEM, time.Now(), hostID,
	)
	if err != nil {
		return fmt.Errorf("update signing pub: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("update signing pub rows affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Enrollment Tokens ---

// CreateHostAndToken atomically creates a host and its enrollment token.
func (s *SQLiteStore) CreateHostAndToken(ctx context.Context, h *models.Host, t *models.EnrollmentToken) error {
	tx, err := s.db.BeginTx(ctx, nil)
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
	advancedJSON, err := marshalAdvanced(h.Advanced)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO hosts (id, network_id, name, groups_json, role, is_lighthouse, is_relay, public_ip, listen_port, status, created_at, updated_at, advanced_json, ca_id, kind, variant)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ID, h.NetworkID, h.Name, string(groupsJSON),
		h.Role, h.IsLighthouse, h.IsRelay, h.PublicIP, h.ListenPort,
		h.Status, h.CreatedAt, h.UpdatedAt, advancedJSON, h.CAID,
		string(h.Kind), string(h.Variant),
	)
	if err != nil {
		return fmt.Errorf("insert host: %w", err)
	}

	if err := s.setHostAddresses(ctx, tx, h.ID, h.NebulaIPs); err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO enrollment_tokens (id, host_id, token_hash, used, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.HostID, t.TokenHash, false, t.ExpiresAt, t.CreatedAt,
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
		`INSERT INTO enrollment_tokens (id, host_id, token_hash, used, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, t.HostID, t.TokenHash, false, t.ExpiresAt, t.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	return nil
}

// CreateTokenForHost atomically invalidates any active enrollment tokens for
// the host and writes a fresh single-use one. Used by the regenerate-token,
// reenroll, and rekey flows (ADR 0004) where the host row must be preserved.
// The `token` argument is the raw value handed back to the caller; the store
// only ever persists its SHA-256 hex (GHSA-ghmh-jhmj-wcmf).
func (s *SQLiteStore) CreateTokenForHost(_ context.Context, hostID, token string, expiresAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback", "error", err)
		}
	}()

	if _, err := tx.Exec(`DELETE FROM enrollment_tokens WHERE host_id = ? AND used = 0`, hostID); err != nil {
		return fmt.Errorf("delete previous tokens: %w", err)
	}
	now := time.Now()
	id := fmt.Sprintf("etok_%d", now.UnixNano())
	if _, err := tx.Exec(
		`INSERT INTO enrollment_tokens (id, host_id, token_hash, used, expires_at, created_at) VALUES (?, ?, ?, 0, ?, ?)`,
		id, hostID, models.HashEnrollmentToken(token), expiresAt, now,
	); err != nil {
		return fmt.Errorf("insert token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit create token: %w", err)
	}
	return nil
}

// ConsumeToken accepts the raw token from the caller, hashes it, and
// looks up by SHA-256 hex. Marks the row used on success. GHSA-ghmh-jhmj-wcmf.
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
		`SELECT id, host_id, token_hash, used, expires_at, created_at FROM enrollment_tokens WHERE token_hash = ?`,
		models.HashEnrollmentToken(token),
	).Scan(&t.ID, &t.HostID, &t.TokenHash, &t.Used, &t.ExpiresAt, &t.CreatedAt)
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
// If the host has role=lighthouse, the network's config_version is bumped so peer
// agents pick up the new lighthouse on their next poll.
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

	var isLighthouse bool
	var networkID string
	err = tx.QueryRow(
		`SELECT is_lighthouse, network_id FROM hosts WHERE id = ?`, hostID,
	).Scan(&isLighthouse, &networkID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get host role: %w", err)
	}

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

	if isLighthouse {
		if _, err := tx.Exec(
			`UPDATE networks SET config_version = config_version + 1 WHERE id = ?`,
			networkID,
		); err != nil {
			return fmt.Errorf("bump config version: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit enroll host: %w", err)
	}
	return nil
}

// SaveCertificateAndUpdateHostCert atomically saves a certificate and
// updates the host's cert metadata. The previous fingerprint (if non-empty)
// is parked in prev_cert_fingerprint with cert_rotated_at = now() so the
// poll handler can accept either fingerprint during the rotation overlap
// window (ADR 0004 §7.1).
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

	now := time.Now()
	// Park the prior fingerprint (only when it actually differs from the
	// new one). Same-key rotation handing back the same fingerprint should
	// not populate prev_cert_fingerprint; the agent's poll continues to
	// match on cert_fingerprint.
	result, err := tx.Exec(
		`UPDATE hosts SET
			prev_cert_fingerprint = CASE
				WHEN cert_fingerprint IS NULL OR cert_fingerprint = '' OR cert_fingerprint = ? THEN prev_cert_fingerprint
				ELSE cert_fingerprint
			END,
			cert_rotated_at = CASE
				WHEN cert_fingerprint IS NULL OR cert_fingerprint = '' OR cert_fingerprint = ? THEN cert_rotated_at
				ELSE ?
			END,
			cert_fingerprint = ?,
			cert_expires_at  = ?,
			updated_at       = ?
		 WHERE id = ?`,
		fp, fp, now, fp, notAfter, now, hostID,
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

	// Inherit ca_id from the host so the startup invariant (no empty ca_id
	// rows across networks/hosts/certificates/blocklist) holds after enrol /
	// rotate / mobile-bundle paths complete.
	var caID string
	if err := tx.QueryRow(`SELECT ca_id FROM hosts WHERE id = ?`, hostID).Scan(&caID); err != nil {
		return fmt.Errorf("get host ca_id for cert insert: %w", err)
	}

	prefix := hostID
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	id := fmt.Sprintf("cert_%s_%d", prefix, time.Now().UnixNano())
	_, err = tx.Exec(
		`INSERT INTO certificates (id, host_id, ca_id, fingerprint, pem, not_before, not_after, is_current, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
		id, hostID, caID, fp, string(certPEM), notBefore, notAfter, time.Now(),
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

// --- Cert-expiry alert dedup ---

// RecordCertAlert upserts the (host_id, alerted_not_after) tuple so subsequent
// scans for the same cert do not re-emit the alert. Update alerted_at to now
// on every call so dashboards can show "last fired" times.
func (s *SQLiteStore) RecordCertAlert(_ context.Context, hostID string, alertedNotAfter time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO cert_alerts (host_id, alerted_not_after, alerted_at) VALUES (?, ?, ?)
		 ON CONFLICT(host_id) DO UPDATE SET alerted_not_after = excluded.alerted_not_after, alerted_at = excluded.alerted_at`,
		hostID, alertedNotAfter, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("record cert alert: %w", err)
	}
	return nil
}

// GetCertAlert returns the alerted_not_after recorded for hostID, or
// ErrNotFound when no alert has been recorded yet.
func (s *SQLiteStore) GetCertAlert(_ context.Context, hostID string) (time.Time, error) {
	var t time.Time
	err := s.db.QueryRow(`SELECT alerted_not_after FROM cert_alerts WHERE host_id = ?`, hostID).Scan(&t)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get cert alert: %w", err)
	}
	return t, nil
}

// --- Server settings (key/value) ---

// GetServerSetting returns the stored value for key, or "" + ErrNotFound
// when the key has never been set.
func (s *SQLiteStore) GetServerSetting(_ context.Context, key string) (string, error) {
	var value string
	err := s.db.QueryRow(`SELECT value FROM server_settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get server setting: %w", err)
	}
	return value, nil
}

// SetServerSetting upserts a key/value pair into server_settings.
func (s *SQLiteStore) SetServerSetting(_ context.Context, key, value string) error {
	_, err := s.db.Exec(
		`INSERT INTO server_settings (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value,
	)
	if err != nil {
		return fmt.Errorf("set server setting: %w", err)
	}
	return nil
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

func (s *SQLiteStore) GetHostConfigVersion(_ context.Context, hostID string) (int, error) {
	var version int
	err := s.db.QueryRow(`SELECT config_version FROM hosts WHERE id = ?`, hostID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("get host config version: %w", err)
	}
	return version, nil
}

func (s *SQLiteStore) UpdateHostConfigVersion(_ context.Context, hostID string, version int) error {
	result, err := s.db.Exec(
		`UPDATE hosts SET config_version=?, updated_at=? WHERE id=?`,
		version, time.Now(), hostID,
	)
	if err != nil {
		return fmt.Errorf("update host config version: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("update host config version rows affected: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
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
