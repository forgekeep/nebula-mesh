// Package fsutil holds small filesystem helpers shared across the agent and
// server. AtomicWriteFile is the durable temp-file → rename pattern that the
// agent's config writer and both config savers previously each reimplemented
// (#225), now in one place that also fsyncs the parent directory.
package fsutil

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// AtomicWriteFile writes data to path atomically and durably. It creates a temp
// file in the same directory, fsyncs the file, chmods it to perm, renames it
// over the target, then fsyncs the parent directory so the rename itself
// survives a crash.
//
// The trailing directory fsync is the crash-safety fix: on Linux/Unix the
// rename is not durable until the directory entry is flushed, so after power
// loss the target file could revert to its old content — or, for a first-time
// write, disappear — even though Write, Sync, and Rename all reported success
// (#225). The directory sync is best-effort (some filesystems and platforms do
// not support it) and runs only after the rename has succeeded, so a failure
// there is logged rather than returned: failing here would be misleading when
// the new data is already in place.
func AtomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// cleanup removes the temp file on any failure before the rename lands.
	cleanup := func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			slog.Error("remove temp file", "path", tmpPath, "error", removeErr)
		}
	}

	if _, err := tmp.Write(data); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			slog.Error("close temp file after write error", "path", tmpPath, "error", closeErr)
		}
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			slog.Error("close temp file after sync error", "path", tmpPath, "error", closeErr)
		}
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename temp to target: %w", err)
	}
	syncDir(dir)
	return nil
}

// syncDir flushes the directory entry so a prior rename is durable. Best-effort:
// directory fsync is unsupported on some platforms/filesystems, so errors are
// logged at warn level rather than propagated.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		slog.Warn("open dir for fsync", "dir", dir, "error", err)
		return
	}
	if err := d.Sync(); err != nil {
		slog.Warn("fsync dir", "dir", dir, "error", err)
	}
	if err := d.Close(); err != nil {
		slog.Warn("close dir after fsync", "dir", dir, "error", err)
	}
}
