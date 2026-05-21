package store

import (
	"context"
	"database/sql"
	"testing"
)

// TestMigration_BlocklistHasCAID is the regression test for issue #37 —
// migration 009's multi-statement Exec used to silently drop the
// `ALTER TABLE blocklist ADD COLUMN ca_id` statement on modernc/sqlite,
// leaving blocklist out of sync with the other three tables.
func TestMigration_BlocklistHasCAID(t *testing.T) {
	s := newTestStore(t)
	if !columnExists(t, s, "blocklist", "ca_id") {
		t.Fatal("blocklist is missing the ca_id column after Migrate()")
	}
	idxRows, err := s.DB().Query(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_blocklist_ca';`)
	if err != nil {
		t.Fatal(err)
	}
	defer idxRows.Close()
	if !idxRows.Next() {
		t.Error("idx_blocklist_ca is missing after Migrate()")
	}
}

// TestMigration_StableAcrossRestarts guards against the second half of
// issue #37 — a second Migrate() pass used to silently re-run the
// destructive 004 recreate and then bail out on the duplicate ALTER in
// 009, leaving `blocklist` without `ca_id`. The tracking table fixes that.
func TestMigration_StableAcrossRestarts(t *testing.T) {
	s := newTestStore(t)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("third Migrate: %v", err)
	}
	if !columnExists(t, s, "blocklist", "ca_id") {
		t.Fatal("blocklist lost ca_id across repeated Migrate() calls (regression of #37)")
	}
}

// TestMigration_HealsLegacyMissingCAID exercises the repair path for
// databases that were initialized by the pre-#37 loader and ended up
// without `blocklist.ca_id`. After Migrate(), the column and its index
// must be back.
func TestMigration_HealsLegacyMissingCAID(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.DB().Exec(`CREATE TABLE blocklist_legacy (
		fingerprint TEXT PRIMARY KEY,
		host_id     TEXT REFERENCES hosts(id) ON DELETE SET NULL,
		reason      TEXT,
		created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`INSERT INTO blocklist_legacy SELECT fingerprint, host_id, reason, created_at FROM blocklist`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`DROP TABLE blocklist`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`ALTER TABLE blocklist_legacy RENAME TO blocklist`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`DROP INDEX IF EXISTS idx_blocklist_ca`); err != nil {
		t.Fatal(err)
	}

	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !columnExists(t, s, "blocklist", "ca_id") {
		t.Fatal("repair path did not restore blocklist.ca_id")
	}
}

func TestSplitSQLStatements(t *testing.T) {
	in := `CREATE TABLE foo (
    id   INTEGER PRIMARY KEY,
    name TEXT DEFAULT ''
);

-- comment with ; semicolon inside
ALTER TABLE foo ADD COLUMN extra TEXT DEFAULT 'a; b';
CREATE INDEX idx_foo_extra ON foo(extra);`
	got := splitSQLStatements(in)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3; got=%q", len(got), got)
	}
}

func columnExists(t *testing.T, s *SQLiteStore, table, column string) bool {
	t.Helper()
	rows, err := s.DB().Query("PRAGMA table_info(" + table + ");")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var dflt sql.NullString
		var notnull, pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		if name == column {
			return true
		}
	}
	return false
}
