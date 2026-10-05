package store

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"modernc.org/sqlite"
)

// SEC-PERSIST-001: db_path comes from the server configuration and its query
// string reaches the driver, where a `_pragma` value runs as SQL text. Strict
// pragmas confine such a value to the one PRAGMA it names.
//
// Without the switch the open succeeds and the ATTACH creates the side file,
// which is what makes this a regression test: dropping StrictPragmas from
// NewSQLiteStore turns it red.
func TestNewSQLiteStore_SEC_PERSIST_001_RejectsMultiStatementPragma(t *testing.T) {
	dir := t.TempDir()
	side := filepath.Join(dir, "side.db")
	pragma := "foreign_keys(1);ATTACH '" + side + "' AS side"
	dbPath := filepath.Join(dir, "store.db") + "?_pragma=" + url.QueryEscape(pragma)

	s, err := NewSQLiteStore(dbPath)
	if err == nil {
		_ = s.Close()
		t.Fatal("store opened with a multi-statement _pragma in db_path, want rejection")
	}
	if !errors.Is(err, sqlite.ErrMultiStatementPragma) {
		t.Fatalf("open error = %v, want ErrMultiStatementPragma", err)
	}
	if _, statErr := os.Stat(side); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("stat side database = %v, want not exist: the trailing statement ran", statErr)
	}
}

// The other half of the contract: the store's own `_pragma` list is three
// single statements, so the switch leaves an ordinary open untouched.
func TestNewSQLiteStore_StrictPragmasKeepsStoreOperational(t *testing.T) {
	s := newTestFileStore(t, "strict-pragmas.db")

	if !sqlite.StrictPragmasEnabled() {
		t.Fatal("StrictPragmas is off after NewSQLiteStore")
	}
	var mode string
	if err := s.DB().QueryRowContext(context.Background(), "PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Fatalf("journal_mode = %q, want wal", mode)
	}
}
