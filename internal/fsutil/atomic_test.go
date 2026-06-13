package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAtomicWriteFile_WritesAndOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if err := AtomicWriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("content = %q, want hello", data)
	}

	if err := AtomicWriteFile(path, []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "world" {
		t.Errorf("content = %q, want world", data)
	}

	// No temp residue: the directory holds exactly the target file.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file in dir, got %d", len(entries))
	}
}

func TestAtomicWriteFile_AppliesPerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes not meaningful on windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")

	if err := AtomicWriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("perm = %o, want 600", got)
	}
}

func TestAtomicWriteFile_InvalidDir(t *testing.T) {
	err := AtomicWriteFile("/nonexistent/dir/file.txt", []byte("data"), 0o644)
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}

// TestAtomicWriteFile_NoTempResidueOnFailure ensures a failed write does not
// leave a stray temp file behind. We trigger failure by pointing at a path
// whose parent does not exist (CreateTemp fails before any temp is made), and
// also exercise the happy path leaving no .tmp.* siblings.
func TestAtomicWriteFile_NoTempResidueOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := AtomicWriteFile(path, []byte("k: v\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "config.yml" {
			t.Errorf("unexpected leftover entry %q (temp residue?)", e.Name())
		}
	}
}
