package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/juev/nebula-mesh/internal/store/migrations"

	_ "modernc.org/sqlite"
)

// migrations017 is the ordered up-migration set preceding 018.
var migrations017 = []string{
	"001_initial.up.sql", "002_config_version.up.sql", "003_audit_log.up.sql",
	"004_blocklist_fk.up.sql", "005_operators.up.sql", "006_operator_totp.up.sql",
	"007_operator_oidc.up.sql", "008_host_advanced.up.sql", "009_per_operator_cas.up.sql",
	"010_cert_alerts.up.sql", "011_server_settings.up.sql", "012_agent_auth.up.sql",
	"013_host_mobile.up.sql", "014_multi_address.up.sql", "015_ca_predecessor.up.sql",
	"016_enrollment_token_hash.up.sql", "017_pop_nonces.up.sql",
}

func applyMigrationFiles(t *testing.T, db *sql.DB, files []string) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name TEXT PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}
	for _, f := range files {
		b, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, stmt := range splitSQLStatementsForTest(string(b)) {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("apply %s stmt %q: %v", f, stmt, err)
			}
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (name) VALUES (?)", f); err != nil {
			t.Fatalf("record %s: %v", f, err)
		}
	}
}

// execMigrationFile runs each statement of one migration file and returns the
// first error (used to assert intentional fail-loud behavior).
func execMigrationFile(db *sql.DB, file string) error {
	b, err := migrations.FS.ReadFile(file)
	if err != nil {
		return err
	}
	for _, stmt := range splitSQLStatementsForTest(string(b)) {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			return err
		}
	}
	return nil
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

// TestMigration018_BackfillsNetworkID_AndDownRoundTrip verifies the backfill of
// pre-existing host_addresses rows (the SELECT that no store-method test
// exercises, since those create rows after the column exists) and the down
// migration's drop-index-before-drop-column round trip.
func TestMigration018_BackfillsNetworkID_AndDownRoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	applyMigrationFiles(t, db, migrations017)

	// Seed a network + host + a pre-existing host_addresses row (pre-018 schema,
	// no network_id column) so the 018 backfill SELECT is actually exercised.
	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "host-1")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")

	if columnExistsInDB(t, db, "host_addresses", "network_id") {
		t.Fatal("network_id should not exist before 018")
	}

	if err := execMigrationFile(db, "018_host_address_network_uniqueness.up.sql"); err != nil {
		t.Fatalf("apply 018: %v", err)
	}

	if !columnExistsInDB(t, db, "host_addresses", "network_id") {
		t.Fatal("network_id should exist after 018")
	}
	var gotNet string
	if err := db.QueryRowContext(context.Background(),
		`SELECT network_id FROM host_addresses WHERE host_id = ?`, "h1").Scan(&gotNet); err != nil {
		t.Fatalf("read backfilled network_id: %v", err)
	}
	if gotNet != "net1" {
		t.Errorf("backfilled network_id = %q, want net1", gotNet)
	}

	// Down round-trip: index dropped before column.
	if err := execMigrationFile(db, "018_host_address_network_uniqueness.down.sql"); err != nil {
		t.Fatalf("apply 018 down: %v", err)
	}
	if columnExistsInDB(t, db, "host_addresses", "network_id") {
		t.Error("network_id should be gone after 018 down")
	}
}

// TestMigration018_FailsLoudOnDuplicateOverlayIP pins the deliberate fail-safe:
// if a database already holds two hosts sharing one overlay IP in a network (the
// security defect this migration exists to prevent), CREATE UNIQUE INDEX must
// abort the migration rather than silently tolerate it.
func TestMigration018_FailsLoudOnDuplicateOverlayIP(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	applyMigrationFiles(t, db, migrations017)

	mustExec(t, db, `INSERT INTO networks (id, name) VALUES (?, ?)`, "net1", "n1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h1", "net1", "host-1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name) VALUES (?, ?, ?)`, "h2", "net1", "host-2")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h1", 0, "10.0.0.5")
	mustExec(t, db, `INSERT INTO host_addresses (host_id, position, address) VALUES (?, ?, ?)`, "h2", 0, "10.0.0.5")

	err = execMigrationFile(db, "018_host_address_network_uniqueness.up.sql")
	if err == nil {
		t.Fatal("018 must fail loud on a pre-existing duplicate overlay IP, but succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Errorf("018 failure = %v, want a UNIQUE constraint error", err)
	}
}
