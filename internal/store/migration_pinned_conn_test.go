package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/store/migrations"
)

// TestMigrate_PinnedConnection_SurvivesPoolDispersal pins the fix for the
// connection-scoped PRAGMA hazard in migration 014 (L12, 2026-06-12 audit).
//
// 014 runs `PRAGMA foreign_keys = OFF`, drops + recreates hosts/networks,
// then turns the pragma back ON — as separate statements. The pragma is
// connection-scoped, and every pool connection opens with foreign_keys(on)
// via the DSN. If the OFF and the `DROP TABLE hosts` execute on different
// pooled connections, the drop's implicit DELETE FROM runs with FK
// enforcement live and cascade-deletes every child row: certificates,
// host_addresses (backfilled earlier in the same migration), and
// enrollment_tokens.
//
// SetMaxIdleConns(0) makes the dispersal deterministic — no connection ever
// goes idle, so consecutive pool Execs use distinct fresh connections.
// Against the unpinned loader this test fails with empty child tables;
// Migrate now pins one *sql.Conn for the whole run.
func TestMigrate_PinnedConnection_SurvivesPoolDispersal(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "migrate.db")
	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.db.SetMaxIdleConns(0)

	// Build a pre-014 database: apply 001..013 manually, then seed a
	// network, a host, a certificate, and an enrollment token.
	pre014 := []string{
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
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name        TEXT PRIMARY KEY,
		applied_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	for _, f := range pre014 {
		sqlBytes, err := migrations.FS.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, stmt := range splitSQLStatementsForTest(string(sqlBytes)) {
			if _, err := s.db.ExecContext(ctx, stmt); err != nil {
				t.Fatalf("apply %s: %v", f, err)
			}
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_migrations (name) VALUES (?)`, f); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO networks (id, name, cidr, created_at, ca_id) VALUES (?, ?, ?, ?, ?)`,
		"net-1", "prod", "10.42.0.0/24", time.Now(), "ca-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO hosts (id, network_id, name, nebula_ip, groups_json, status, ca_id)
		 VALUES (?, ?, ?, ?, '[]', 'active', 'ca-1')`,
		"host-1", "net-1", "web-1", "10.42.0.5"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO certificates (id, host_id, fingerprint, pem, not_before, not_after, ca_id)
		 VALUES (?, ?, ?, ?, ?, ?, 'ca-1')`,
		"cert-1", "host-1", "fp-1", "PEM", time.Now(), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO enrollment_tokens (id, host_id, token, expires_at) VALUES (?, ?, ?, ?)`,
		"etok-1", "host-1", "tok-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Run the production loader for the remaining migrations (014+).
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// Every child row must survive 014's table recreation.
	for _, q := range []struct{ name, query string }{
		{"certificates", `SELECT COUNT(1) FROM certificates WHERE host_id = 'host-1'`},
		{"host_addresses", `SELECT COUNT(1) FROM host_addresses WHERE host_id = 'host-1'`},
		{"enrollment_tokens", `SELECT COUNT(1) FROM enrollment_tokens WHERE host_id = 'host-1'`},
	} {
		var n int
		if err := s.db.QueryRowContext(ctx, q.query).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", q.name, err)
		}
		if n != 1 {
			t.Errorf("%s rows for host-1 = %d, want 1 (cascade-deleted during migration 014)", q.name, n)
		}
	}
}

// TestMigrate_ForeignKeysEnforcedAfterMigrate asserts FK enforcement is live
// on pool connections after Migrate returns — the pinned migration
// connection must not leak a foreign_keys=OFF state back into the pool.
func TestMigrate_ForeignKeysEnforcedAfterMigrate(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "fk.db")
	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// An insert referencing a missing parent must fail.
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO certificates (id, host_id, fingerprint, pem, not_before, not_after, ca_id)
		 VALUES ('c-orphan', 'no-such-host', 'fp-x', 'PEM', ?, ?, 'ca-x')`,
		time.Now(), time.Now().Add(time.Hour))
	if err == nil {
		t.Fatal("orphan certificate insert succeeded — foreign_keys not enforced after Migrate")
	}
}
