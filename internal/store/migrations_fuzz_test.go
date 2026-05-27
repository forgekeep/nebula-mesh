package store

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/store/migrations"
)

// applyMigrationsBefore runs every up-migration that sorts before stopAt and
// records it in schema_migrations, leaving the DB at the schema version right
// before stopAt. It lets a fuzz target seed rows in the pre-migration shape and
// then exercise the remaining migrations' transforms on that data.
func applyMigrationsBefore(tb testing.TB, s *SQLiteStore, stopAt string) {
	tb.Helper()
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name        TEXT PRIMARY KEY,
		applied_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		tb.Fatalf("create schema_migrations: %v", err)
	}
	// Sorted *.up.sql reproduces Migrate's hardcoded migrationFiles order, which
	// holds as long as migrations keep their zero-padded numeric prefix (NNN_).
	files, err := fs.Glob(migrations.FS, "*.up.sql")
	if err != nil {
		tb.Fatalf("glob migrations: %v", err)
	}
	sort.Strings(files)
	for _, f := range files {
		if f == stopAt {
			return
		}
		b, err := migrations.FS.ReadFile(f)
		if err != nil {
			tb.Fatalf("read %s: %v", f, err)
		}
		if _, err := s.db.ExecContext(ctx, string(b)); err != nil {
			tb.Fatalf("apply %s: %v", f, err)
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO schema_migrations (name) VALUES (?)`, f); err != nil {
			tb.Fatalf("record %s: %v", f, err)
		}
	}
}

// FuzzMigrations checks the migration chain for totality on schema-plausible
// legacy data (ADR 0009 Tier 1). It seeds a network and N hosts in the pre-014
// single-address shape with fuzzed overlay-IP strings, then runs the remaining
// migrations — exercising 014's nebula_ip -> host_addresses backfill and 018's
// network-scoped uniqueness index on whatever bytes the fuzzer supplies.
// Properties:
//
//   - totality: Migrate completes without panicking or erroring on data the
//     pre-014 schema accepted, and never half-applies;
//
//   - idempotency: a second Migrate is a clean no-op;
//
//   - backfill conservation: every legacy nebula_ip becomes exactly one
//     host_addresses row — none dropped, none duplicated.
//
// Run the seed corpus with the unit tests; explore with
//
//	go test ./internal/store/ -run '^$' -fuzz='^FuzzMigrations$'
func FuzzMigrations(f *testing.F) {
	f.Add("10.0.0.0/24", []byte("10.0.0.5\n10.0.0.6\nfd00::1"))
	f.Add("", []byte(""))
	f.Add("not-a-cidr", []byte("not-an-ip\n\n  \nx"))

	f.Fuzz(func(t *testing.T, cidr string, data []byte) {
		s, err := NewSQLiteStore(":memory:")
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		defer s.Close()
		ctx := context.Background()

		applyMigrationsBefore(t, s, "014_multi_address.up.sql")

		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO networks (id, name, cidr) VALUES ('net1', 'n1', ?)`, cidr); err != nil {
			t.Fatalf("seed network: %v", err)
		}

		// Distinct, non-empty overlay IPs: the pre-014 UNIQUE(network_id,
		// nebula_ip) and UNIQUE(network_id, name) constraints require both, so
		// dedup here rather than letting an insert fail the seed.
		seen := make(map[string]bool)
		seeded := 0
		for _, ip := range strings.Split(string(data), "\n") {
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			if _, err := s.db.ExecContext(ctx,
				`INSERT INTO hosts (id, network_id, name, nebula_ip) VALUES (?, 'net1', ?, ?)`,
				fmt.Sprintf("h%d", seeded), fmt.Sprintf("name%d", seeded), ip); err != nil {
				t.Fatalf("seed host %q: %v", ip, err)
			}
			seeded++
		}

		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("Migrate failed on schema-plausible legacy data (cidr=%q, hosts=%d): %v", cidr, seeded, err)
		}
		if err := s.Migrate(ctx); err != nil {
			t.Fatalf("second Migrate was not idempotent: %v", err)
		}

		var addrCount int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_addresses`).Scan(&addrCount); err != nil {
			t.Fatalf("count host_addresses: %v", err)
		}
		if addrCount != seeded {
			t.Fatalf("backfill not conserved: host_addresses=%d, seeded legacy IPs=%d", addrCount, seeded)
		}
	})
}
