package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

var migrations026 = append(append([]string{}, migrations025...),
	"026_redeliver_wdf_config.up.sql",
)

func TestMigration027_SEC_CREDENTIAL_001_RejectsCollectingImportAtomically(t *testing.T) {
	path := t.TempDir() + "/store.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	applyMigrationFiles(t, db, migrations026)
	seedMigration027Operator(t, db)
	mustExec(t, db, `INSERT INTO operator_sessions (token_hash, operator_id, expires_at) VALUES (?, ?, ?)`,
		strings.Repeat("a", 64), "op-1", time.Now().Add(time.Hour))
	seedMigration027MeshImport(t, db, "import-collecting", "collecting", strings.Repeat("b", 64))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := NewSQLiteStore(path, WithCredentialCutoverGuard(func(context.Context, *SQLiteStore) error {
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.Migrate(context.Background())
	if !errors.Is(err, ErrCredentialCutoverBlocked) {
		t.Fatalf("Migrate() error = %v, want ErrCredentialCutoverBlocked", err)
	}

	var sessions int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM operator_sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("sessions after rejected migration = %d, want 1", sessions)
	}
	var applied int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE name = ?`,
		"027_keyed_credential_cutover.up.sql").Scan(&applied); err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Fatalf("migration marker count = %d, want 0", applied)
	}
}

func TestMigration027_SEC_CREDENTIAL_001_InvalidatesAndScrubsLegacyCredentials(t *testing.T) {
	path := t.TempDir() + "/store.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	applyMigrationFiles(t, db, migrations026)
	seedMigration027Operator(t, db)
	mustExec(t, db, `INSERT INTO operator_api_keys (id, operator_id, key_hash) VALUES (?, ?, ?)`,
		"key-1", "op-1", strings.Repeat("a", 64))
	mustExec(t, db, `INSERT INTO operator_sessions (token_hash, operator_id, expires_at) VALUES (?, ?, ?)`,
		strings.Repeat("b", 64), "op-1", time.Now().Add(time.Hour))
	mustExec(t, db, `INSERT INTO operator_recovery_codes (operator_id, code_hash) VALUES (?, ?)`,
		"op-1", strings.Repeat("c", 64))
	mustExec(t, db, `INSERT INTO enrollment_tokens (id, host_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
		"token-1", "host-1", strings.Repeat("d", 64), time.Now().Add(time.Hour))
	seedMigration027MeshImport(t, db, "import-final", "finalized", strings.Repeat("e", 64))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := NewSQLiteStore(path, WithCredentialCutoverGuard(func(context.Context, *SQLiteStore) error {
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate(): %v", err)
	}

	var keyHash string
	var revokedAt sql.NullTime
	if err := s.db.QueryRow(`SELECT key_hash, revoked_at FROM operator_api_keys WHERE id = 'key-1'`).
		Scan(&keyHash, &revokedAt); err != nil {
		t.Fatal(err)
	}
	if keyHash != "cutover-v1:api-key:key-1" || !revokedAt.Valid {
		t.Fatalf("API key after cutover = (%q, %v)", keyHash, revokedAt.Valid)
	}
	for _, table := range []string{"operator_sessions", "operator_recovery_codes", "enrollment_tokens"} {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("%s rows after cutover = %d, want 0", table, count)
		}
	}
	var meshHash string
	if err := s.db.QueryRow(`SELECT token_hash FROM mesh_imports WHERE id = 'import-final'`).Scan(&meshHash); err != nil {
		t.Fatal(err)
	}
	if meshHash != "cutover-v1:mesh-import:import-final" {
		t.Fatalf("mesh import tombstone = %q", meshHash)
	}
}

func TestMigration027_SEC_CREDENTIAL_001_TriggersRejectPlainSHA256(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "migration-trigger")

	legacy := strings.Repeat("a", 64)
	for _, test := range []struct {
		name string
		sql  string
		args []any
	}{
		{"API key", `INSERT INTO operator_api_keys (id, operator_id, key_hash) VALUES (?, ?, ?)`,
			[]any{"legacy-key", op.ID, legacy}},
		{"session", `INSERT INTO operator_sessions (token_hash, operator_id, expires_at) VALUES (?, ?, ?)`,
			[]any{legacy, op.ID, time.Now().Add(time.Hour)}},
		{"recovery code", `INSERT INTO operator_recovery_codes (operator_id, code_hash) VALUES (?, ?)`,
			[]any{op.ID, legacy}},
		{"enrollment token", `INSERT INTO enrollment_tokens (id, host_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
			[]any{"legacy-token", "missing-host", legacy, time.Now().Add(time.Hour)}},
		{"mesh import", `INSERT INTO mesh_imports (
				id, network_id, ca_id, owner_operator_id, ca_fingerprint, status,
				token_hash, token_expires_at, captured_network_config_version
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			[]any{"legacy-import", "missing-network", "missing-ca", op.ID, "fingerprint",
				"collecting", legacy, time.Now().Add(time.Hour), 1}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := s.db.ExecContext(ctx, test.sql, test.args...); err == nil {
				t.Fatal("plain SHA-256 verifier was accepted")
			}
		})
	}

	valid := "hmac-sha256-v1:" + strings.Repeat("a", 64)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO operator_api_keys (id, operator_id, key_hash) VALUES (?, ?, ?)`,
		"hmac-key", op.ID, valid); err != nil {
		t.Fatalf("canonical HMAC verifier rejected: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE operator_api_keys SET key_hash = ? WHERE id = ?`,
		strings.Repeat("b", 64), "hmac-key"); err == nil {
		t.Fatal("plain SHA-256 API-key update was accepted")
	}
}

func TestMigration027_SEC_CREDENTIAL_001_GuardFailureLeavesCredentialsIntact(t *testing.T) {
	path := t.TempDir() + "/store.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	applyMigrationFiles(t, db, migrations026)
	seedMigration027Operator(t, db)
	mustExec(t, db, `INSERT INTO operator_sessions (token_hash, operator_id, expires_at) VALUES (?, ?, ?)`,
		strings.Repeat("a", 64), "op-1", time.Now().Add(time.Hour))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	guardErr := errors.New("master key mismatch")
	s, err := NewSQLiteStore(path, WithCredentialCutoverGuard(func(context.Context, *SQLiteStore) error {
		return guardErr
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); !errors.Is(err, guardErr) {
		t.Fatalf("Migrate() error = %v, want %v", err, guardErr)
	}
	var sessions int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM operator_sessions`).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("sessions after guard failure = %d, want 1", sessions)
	}
}

func seedMigration027Operator(t *testing.T, db *sql.DB) {
	t.Helper()
	mustExec(t, db, `INSERT INTO operators (id, username, password_hash) VALUES (?, ?, ?)`,
		"op-1", "operator", "password-hash")
	now := time.Now()
	mustExec(t, db, `INSERT INTO cas (
		id, name, owner_operator_id, cert_pem, fingerprint, not_before, not_after,
		encrypted_key_dek, nonce_dek, encrypted_key_material, nonce_key
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"ca-1", "CA", "op-1", "certificate", "ca-fingerprint",
		now.Add(-time.Hour), now.Add(time.Hour), []byte("dek"), []byte("nonce"),
		[]byte("material"), []byte("nonce"))
	mustExec(t, db, `INSERT INTO networks (id, name, ca_id) VALUES (?, ?, ?)`,
		"network-1", "Network", "ca-1")
	mustExec(t, db, `INSERT INTO hosts (id, network_id, name, ca_id) VALUES (?, ?, ?, ?)`,
		"host-1", "network-1", "Host", "ca-1")
}

func seedMigration027MeshImport(t *testing.T, db *sql.DB, id, status, tokenHash string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO mesh_imports (
		id, network_id, ca_id, owner_operator_id, ca_fingerprint, status,
		token_hash, token_expires_at, captured_network_config_version
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "network-1", "ca-1", "op-1", "ca-fingerprint", status,
		tokenHash, time.Now().Add(time.Hour), 1)
}
