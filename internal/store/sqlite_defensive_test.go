package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// newTestFileStore opens a migrated, file-backed store. File-backed is the
// point: an in-memory database has no journal file to switch off, and the
// probes below need a database whose schema state is otherwise mutable.
func newTestFileStore(t *testing.T, name string) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), name), WithCredentialHasher(newTestCredentialHasher(t)))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// SEC-PERSIST-001: the store connection carries SQLite's defensive mode, so the
// SQL routes that rewrite the file holding CA records, hosts and enrollment
// state are refused by the engine instead of merely being unused.
//
// Both probes are silently accepted without the flag — the schema version moves
// and the delete runs — which is what makes this a regression test rather than
// a restatement: dropping `_defensive` from the DSN turns it red.
func TestNewSQLiteStore_SEC_PERSIST_001_DefensiveModeProtectsSchema(t *testing.T) {
	s := newTestFileStore(t, "defensive-schema.db")
	ctx := context.Background()

	var before, after int64
	if err := s.DB().QueryRowContext(ctx, "PRAGMA schema_version").Scan(&before); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx, fmt.Sprintf("PRAGMA schema_version=%d", before+41)); err != nil {
		t.Fatalf("PRAGMA schema_version: %v", err)
	}
	if err := s.DB().QueryRowContext(ctx, "PRAGMA schema_version").Scan(&after); err != nil {
		t.Fatalf("re-read schema_version: %v", err)
	}
	if after != before {
		t.Fatalf("schema_version changed from %d to %d: defensive mode is not in effect", before, after)
	}

	// writable_schema=ON is the door to rewriting sqlite_schema directly. Under
	// defensive mode the PRAGMA reports success and the door stays shut, so the
	// delete that follows must be refused and the row must survive it.
	if _, err := s.DB().ExecContext(ctx, "PRAGMA writable_schema=ON"); err != nil {
		t.Fatalf("PRAGMA writable_schema=ON: %v", err)
	}
	if _, err := s.DB().ExecContext(ctx, "DELETE FROM sqlite_schema WHERE name = 'schema_migrations'"); err == nil {
		t.Fatal("direct sqlite_schema write succeeded, want rejection under defensive mode")
	}
	var remaining int
	if err := s.DB().QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name = 'schema_migrations'").Scan(&remaining); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("schema_migrations rows = %d after a rejected write, want 1", remaining)
	}
}

// The other half of the contract: the flag restricts schema-level writes and
// nothing else the store does. Migrations already ran in the fixture; this
// exercises an ordinary write path and the VACUUM INTO snapshot the backup path
// takes (internal/backup/archive.go:100, reached with this same handle from
// internal/cli/ops_backup.go:49).
func TestNewSQLiteStore_DefensiveModeKeepsStoreOperational(t *testing.T) {
	s := newTestFileStore(t, "defensive-workload.db")
	ctx := context.Background()

	createTestNetwork(t, s)
	networks, err := s.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(networks) != 1 {
		t.Fatalf("ListNetworks returned %d networks, want 1", len(networks))
	}

	snap := filepath.Join(t.TempDir(), "snapshot.db")
	// #nosec G202 -- VACUUM INTO takes a quoted string literal, not a bind
	// parameter; snap is our own t.TempDir() path, not user input.
	if _, err := s.DB().ExecContext(ctx, "VACUUM INTO '"+snap+"'"); err != nil {
		t.Fatalf("VACUUM INTO under defensive mode: %v", err)
	}
	info, err := os.Stat(snap)
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("snapshot is empty")
	}
}
