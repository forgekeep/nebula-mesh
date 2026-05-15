package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/store/migrations"

	_ "modernc.org/sqlite"
)

// TestMigration015_RoundTrip verifies that migration 015 adds the predecessor_id
// column to the cas table, and that rollback via the down migration removes it.
func TestMigration015_RoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Create schema_migrations tracking table.
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name        TEXT PRIMARY KEY,
		applied_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("create schema_migrations: %v", err)
	}

	// Apply migrations 001-014.
	migrations014 := []string{
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
	}

	for _, f := range migrations014 {
		sqlBytes, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatalf("read migration %s: %v", f, err)
		}
		for _, stmt := range splitSQLStatementsForTest(string(sqlBytes)) {
			if _, err := db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("apply migration %s stmt: %v", f, err)
			}
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO schema_migrations (name) VALUES (?)", f); err != nil {
			t.Fatalf("record migration %s: %v", f, err)
		}
	}

	// Verify predecessor_id column does not exist before migration 015.
	if columnExistsInDB(t, db, "cas", "predecessor_id") {
		t.Fatalf("column cas.predecessor_id should not exist before migration 015")
	}

	// Apply migration 015.
	migr015Bytes, err := migrations.FS.ReadFile("015_ca_predecessor.up.sql")
	if err != nil {
		t.Fatalf("read migration 015 up: %v", err)
	}
	for _, stmt := range splitSQLStatementsForTest(string(migr015Bytes)) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply migration 015 up stmt: %v", err)
		}
	}

	// Verify predecessor_id column exists after migration 015.
	if !columnExistsInDB(t, db, "cas", "predecessor_id") {
		t.Fatalf("column cas.predecessor_id should exist after migration 015")
	}

	// Create an operator first (needed for CA foreign key).
	opID := "op_test_015"
	if _, err := db.ExecContext(ctx, `
		INSERT INTO operators (id, username, password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, opID, "testop", "hash", time.Now(), time.Now()); err != nil {
		t.Fatalf("insert operator: %v", err)
	}

	// Create two CAs: oldCA and newCA.
	oldCAID := "ca_old_015"
	newCAID := "ca_new_015"
	now := time.Now()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO cas (id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, oldCAID, "old-ca", opID, "cert_pem", "fp_old", now, now.AddDate(10, 0, 0), "active", []byte("key"), []byte("nonce"), []byte("material"), []byte("nonce_key"), now, now); err != nil {
		t.Fatalf("insert old CA: %v", err)
	}

	if _, err := db.ExecContext(ctx, `
		INSERT INTO cas (id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after, status, encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key, predecessor_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, newCAID, "new-ca", opID, "cert_pem", "fp_new", now, now.AddDate(10, 0, 0), "active", []byte("key"), []byte("nonce"), []byte("material"), []byte("nonce_key"), oldCAID, now, now); err != nil {
		t.Fatalf("insert new CA with predecessor: %v", err)
	}

	// Verify we can read back the CA with predecessor_id.
	var gotPredecessorID *string
	if err := db.QueryRowContext(ctx, `
		SELECT predecessor_id FROM cas WHERE id = ?
	`, newCAID).Scan(&gotPredecessorID); err != nil {
		t.Fatalf("query new CA predecessor_id: %v", err)
	}
	if gotPredecessorID == nil || *gotPredecessorID != oldCAID {
		t.Errorf("new CA predecessor_id = %v, want %q", gotPredecessorID, oldCAID)
	}

	// Verify old CA has null predecessor_id.
	var oldCAPredecessor *string
	if err := db.QueryRowContext(ctx, `
		SELECT predecessor_id FROM cas WHERE id = ?
	`, oldCAID).Scan(&oldCAPredecessor); err != nil {
		t.Fatalf("query old CA predecessor_id: %v", err)
	}
	if oldCAPredecessor != nil {
		t.Errorf("old CA predecessor_id = %v, want nil", oldCAPredecessor)
	}

	// Apply migration 015 down.
	migr015DownBytes, err := migrations.FS.ReadFile("015_ca_predecessor.down.sql")
	if err != nil {
		t.Fatalf("read migration 015 down: %v", err)
	}
	for _, stmt := range splitSQLStatementsForTest(string(migr015DownBytes)) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply migration 015 down stmt: %v", err)
		}
	}

	// Verify predecessor_id column is removed after rollback.
	if columnExistsInDB(t, db, "cas", "predecessor_id") {
		t.Fatalf("column cas.predecessor_id should not exist after migration 015 down")
	}

	// Verify CAs are still there (columns that are not predecessor_id).
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cas`).Scan(&count); err != nil {
		t.Fatalf("count CAs after down: %v", err)
	}
	if count != 2 {
		t.Errorf("cas table has %d rows, want 2 after migration down", count)
	}

	// Apply migration 015 up again to test re-application (idempotence).
	for _, stmt := range splitSQLStatementsForTest(string(migr015Bytes)) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply migration 015 up again: %v", err)
		}
	}

	// Verify predecessor_id column exists again.
	if !columnExistsInDB(t, db, "cas", "predecessor_id") {
		t.Fatalf("column cas.predecessor_id should exist after re-applying migration 015")
	}
}
