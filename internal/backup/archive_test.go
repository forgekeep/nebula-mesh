package backup

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// makeDB opens a WAL-mode SQLite database at a temp path, seeds a row, and
// returns the open handle plus its path. VACUUM INTO must see the seeded row
// even though it lives in the WAL.
func makeDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "src.db")
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO kv VALUES ('hello', 'world')`); err != nil {
		t.Fatal(err)
	}
	return db, path
}

func readKV(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT v FROM kv WHERE k = 'hello'`).Scan(&v); err != nil {
		t.Fatalf("read restored row: %v", err)
	}
	return v
}

func testMeta() Meta {
	return Meta{AppVersion: "v9.9.9", SchemaVersion: "020_x", Now: time.Unix(1_700_000_000, 0)}
}

func TestCreateRestore_RoundTrip(t *testing.T) {
	db, _ := makeDB(t)
	var buf bytes.Buffer
	if err := Create(context.Background(), db, &buf, testMeta(), "", t.TempDir()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "restored.db")
	manifest, err := Restore(bytes.NewReader(buf.Bytes()), dest, "")
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if got := readKV(t, dest); got != "world" {
		t.Errorf("restored value = %q, want world", got)
	}
	if manifest.AppVersion != "v9.9.9" || manifest.SchemaVersion != "020_x" || manifest.FormatVersion != FormatVersion {
		t.Errorf("manifest = %+v, want app v9.9.9 / schema 020_x / format %d", manifest, FormatVersion)
	}
}

func TestCreateRestore_Encrypted(t *testing.T) {
	db, _ := makeDB(t)
	const pass = "correct horse battery staple"
	var buf bytes.Buffer
	if err := Create(context.Background(), db, &buf, testMeta(), pass, t.TempDir()); err != nil {
		t.Fatalf("Create encrypted: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte(encMagic)) {
		t.Fatal("encrypted archive missing magic header")
	}

	// Correct passphrase round-trips.
	dest := filepath.Join(t.TempDir(), "ok.db")
	if _, err := Restore(bytes.NewReader(buf.Bytes()), dest, pass); err != nil {
		t.Fatalf("Restore with correct passphrase: %v", err)
	}
	if got := readKV(t, dest); got != "world" {
		t.Errorf("restored value = %q, want world", got)
	}

	// Wrong passphrase fails closed.
	if _, err := Restore(bytes.NewReader(buf.Bytes()), filepath.Join(t.TempDir(), "x.db"), "wrong"); !errors.Is(err, ErrDecryptFailed) {
		t.Errorf("wrong passphrase err = %v, want ErrDecryptFailed", err)
	}

	// Missing passphrase on an encrypted archive is reported, not a panic.
	if _, err := Restore(bytes.NewReader(buf.Bytes()), filepath.Join(t.TempDir(), "y.db"), ""); !errors.Is(err, ErrPassphraseRequired) {
		t.Errorf("missing passphrase err = %v, want ErrPassphraseRequired", err)
	}
}

func TestRestore_RefusesExistingDestination(t *testing.T) {
	db, _ := makeDB(t)
	var buf bytes.Buffer
	if err := Create(context.Background(), db, &buf, testMeta(), "", t.TempDir()); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "exists.db")
	if _, err := Restore(bytes.NewReader(buf.Bytes()), dest, ""); err != nil {
		t.Fatal(err)
	}
	// Second restore to the same path must refuse (O_EXCL).
	if _, err := Restore(bytes.NewReader(buf.Bytes()), dest, ""); err == nil {
		t.Error("expected error restoring over an existing destination")
	}
}

func TestRestore_RejectsCorruptArchive(t *testing.T) {
	_, err := Restore(bytes.NewReader([]byte("not a valid archive")), filepath.Join(t.TempDir(), "z.db"), "")
	if !errors.Is(err, ErrCorruptArchive) {
		t.Errorf("err = %v, want ErrCorruptArchive", err)
	}
}
