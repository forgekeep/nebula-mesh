package store

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// migrations018 is the ordered up-migration set preceding 019.
var migrations018 = append(append([]string{}, migrations017...),
	"018_host_address_network_uniqueness.up.sql",
)

// TestMigration019_RenamesTokenToHash_AndDownRoundTrip verifies the
// operator_sessions.token → token_hash rename (GHSA-q4vm-pq3q-8wgq) and the
// down migration's reverse rename.
func TestMigration019_RenamesTokenToHash_AndDownRoundTrip(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	applyMigrationFiles(t, db, migrations018)

	if !columnExistsInDB(t, db, "operator_sessions", "token") {
		t.Fatal("token column should exist before 019")
	}
	if columnExistsInDB(t, db, "operator_sessions", "token_hash") {
		t.Fatal("token_hash should not exist before 019")
	}

	if err := execMigrationFile(db, "019_session_token_hash.up.sql"); err != nil {
		t.Fatalf("apply 019: %v", err)
	}

	if columnExistsInDB(t, db, "operator_sessions", "token") {
		t.Error("token column should be gone after 019")
	}
	if !columnExistsInDB(t, db, "operator_sessions", "token_hash") {
		t.Error("token_hash should exist after 019")
	}

	// token_hash must remain the primary key: a duplicate value is rejected.
	mustExec(t, db, `INSERT INTO operators (id, username, display_name, password_hash) VALUES ('op1','u1','U1','h')`)
	mustExec(t, db, `INSERT INTO operator_sessions (token_hash, operator_id, expires_at, created_at, state) VALUES ('h1','op1','2999-01-01','2000-01-01','authenticated')`)
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO operator_sessions (token_hash, operator_id, expires_at, created_at, state) VALUES ('h1','op1','2999-01-01','2000-01-01','authenticated')`); err == nil {
		t.Error("token_hash should still be the primary key after rename (duplicate accepted)")
	}

	// Down round-trip: token_hash → token.
	if err := execMigrationFile(db, "019_session_token_hash.down.sql"); err != nil {
		t.Fatalf("apply 019 down: %v", err)
	}
	if !columnExistsInDB(t, db, "operator_sessions", "token") {
		t.Error("token column should be back after 019 down")
	}
	if columnExistsInDB(t, db, "operator_sessions", "token_hash") {
		t.Error("token_hash should be gone after 019 down")
	}
}
