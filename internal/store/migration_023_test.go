package store

import (
	"context"
	"database/sql"
	"testing"
)

var migrations022 = append(append([]string{}, migrations017...),
	"018_host_address_network_uniqueness.up.sql",
	"019_session_token_hash.up.sql",
	"020_operator_totp_timestep.up.sql",
	"021_webhook_subscriptions.up.sql",
	"022_operator_lockout.up.sql",
)

func TestMigration023CreatesMeshImportSchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	applyMigrationFiles(t, db, migrations022)
	if err := execMigrationFile(db, "023_mesh_import.up.sql"); err != nil {
		t.Fatalf("apply 023: %v", err)
	}

	for _, table := range []string{
		"mesh_imports",
		"mesh_import_snapshots",
		"host_agent_profiles",
		"mesh_import_challenges",
		"mesh_import_tombstones",
	} {
		if !tableExistsInDB(t, db, table) {
			t.Errorf("table %s does not exist", table)
		}
	}

	for _, index := range []string{
		"ux_mesh_imports_collecting_network",
		"ux_mesh_import_snapshots_fingerprint",
		"idx_mesh_import_challenges_expiry",
		"idx_mesh_import_tombstones_session",
	} {
		if !indexExistsInDB(t, db, index) {
			t.Errorf("index %s does not exist", index)
		}
	}

	assertForeignKey(t, db, "mesh_imports", "network_id", "networks", "id")
	assertForeignKey(t, db, "mesh_imports", "ca_id", "cas", "id")
	assertForeignKey(t, db, "mesh_imports", "owner_operator_id", "operators", "id")
	assertForeignKey(t, db, "mesh_import_snapshots", "mesh_import_id", "mesh_imports", "id")
	assertForeignKey(t, db, "mesh_import_snapshots", "host_id", "hosts", "id")
	assertForeignKey(t, db, "host_agent_profiles", "host_id", "hosts", "id")
	assertForeignKey(t, db, "mesh_import_challenges", "mesh_import_id", "mesh_imports", "id")
	assertForeignKey(t, db, "mesh_import_tombstones", "mesh_import_id", "mesh_imports", "id")
}

func TestMigration023DownRoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	applyMigrationFiles(t, db, migrations022)
	if err := execMigrationFile(db, "023_mesh_import.up.sql"); err != nil {
		t.Fatalf("apply 023: %v", err)
	}
	if err := execMigrationFile(db, "023_mesh_import.down.sql"); err != nil {
		t.Fatalf("rollback 023: %v", err)
	}

	for _, table := range []string{
		"mesh_imports",
		"mesh_import_snapshots",
		"host_agent_profiles",
		"mesh_import_challenges",
		"mesh_import_tombstones",
	} {
		if tableExistsInDB(t, db, table) {
			t.Errorf("table %s still exists after down migration", table)
		}
	}
	if !tableExistsInDB(t, db, "hosts") || !tableExistsInDB(t, db, "networks") {
		t.Fatal("down migration removed pre-existing tables")
	}
}

func TestMigration023UpgradeFrom022AndRepeatedMigrate(t *testing.T) {
	path := t.TempDir() + "/store.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open seed sqlite: %v", err)
	}
	applyMigrationFiles(t, db, migrations022)
	if err := db.Close(); err != nil {
		t.Fatalf("close seed sqlite: %v", err)
	}

	s, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	for i := 0; i < 2; i++ {
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate pass %d: %v", i+1, err)
		}
	}
	if !tableExistsInDB(t, s.db, "mesh_imports") {
		t.Fatal("mesh_imports missing after upgrade")
	}
}

func indexExistsInDB(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, name).Scan(&n); err != nil {
		t.Fatalf("query index %s: %v", name, err)
	}
	return n == 1
}

func assertForeignKey(t *testing.T, db *sql.DB, table, from, target, to string) {
	t.Helper()
	rows, err := db.Query(`PRAGMA foreign_key_list(` + table + `)`)
	if err != nil {
		t.Fatalf("foreign keys for %s: %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, seq int
		var gotTarget, gotFrom, gotTo, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &gotTarget, &gotFrom, &gotTo, &onUpdate, &onDelete, &match); err != nil {
			t.Fatalf("scan foreign key for %s: %v", table, err)
		}
		if gotFrom == from && gotTarget == target && gotTo == to {
			return
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate foreign keys for %s: %v", table, err)
	}
	t.Errorf("foreign key %s.%s -> %s.%s is missing", table, from, target, to)
}
