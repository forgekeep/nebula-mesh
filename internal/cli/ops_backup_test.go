package cli

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

func masterKeyB64(seed byte) string {
	k := make([]byte, 32)
	for i := range k {
		k[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(k)
}

// writeServerConfig writes a minimal server.yml in dir and returns its path and
// the db path it references.
func writeServerConfig(t *testing.T, dir, masterB64 string) (cfgPath, dbPath string) {
	t.Helper()
	dbPath = filepath.Join(dir, "nebula.db")
	cfgPath = filepath.Join(dir, "server.yaml")
	content := `listen: ":8080"
data_dir: "` + dir + `"
db_path: "` + dbPath + `"
log_level: "info"
master_key: "` + masterB64 + `"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dbPath
}

// TestOpsBackupRestore_RoundTripWithMasterKeyCheck initializes a control plane
// (which mints a default CA), backs it up, restores into a fresh data dir under
// the same master key, and asserts the restored CA decrypts.
func TestOpsBackupRestore_RoundTripWithMasterKeyCheck(t *testing.T) {
	t.Setenv("NEBULA_MGMT_MASTER_KEY", "") // force config-file master key
	master := masterKeyB64(1)

	srcDir := t.TempDir()
	srcCfg, _ := writeServerConfig(t, srcDir, master)
	if err := Init(srcCfg); err != nil {
		t.Fatalf("init source: %v", err)
	}

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := OpsBackup(srcCfg, archive, "", "vtest"); err != nil {
		t.Fatalf("OpsBackup: %v", err)
	}
	if fi, err := os.Stat(archive); err != nil || fi.Size() == 0 {
		t.Fatalf("backup archive missing or empty: %v", err)
	}

	dstDir := t.TempDir()
	dstCfg, dstDB := writeServerConfig(t, dstDir, master)
	if err := OpsRestore(dstCfg, archive, "", false); err != nil {
		t.Fatalf("OpsRestore: %v", err)
	}

	// Restored DB carries the minted CA.
	s, err := store.NewSQLiteStore(dstDB)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cas, err := s.ListCAs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) == 0 {
		t.Error("restored database has no CAs")
	}
}

// TestOpsRestore_RefusesWrongMasterKey proves the master-key guard: restoring
// under a key that cannot decrypt the CAs fails loudly.
func TestOpsRestore_RefusesWrongMasterKey(t *testing.T) {
	t.Setenv("NEBULA_MGMT_MASTER_KEY", "")

	srcDir := t.TempDir()
	srcCfg, _ := writeServerConfig(t, srcDir, masterKeyB64(2))
	if err := Init(srcCfg); err != nil {
		t.Fatalf("init source: %v", err)
	}
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := OpsBackup(srcCfg, archive, "", "vtest"); err != nil {
		t.Fatalf("OpsBackup: %v", err)
	}

	// Restore under a different master key.
	dstDir := t.TempDir()
	dstCfg, _ := writeServerConfig(t, dstDir, masterKeyB64(99))
	err := OpsRestore(dstCfg, archive, "", false)
	if err == nil {
		t.Fatal("expected restore to fail under a mismatched master key")
	}
	if !contains(err.Error(), "master key cannot decrypt") {
		t.Errorf("error = %v, want master-key mismatch", err)
	}
}

// TestOpsRestore_RefusesExistingDatabase covers the overwrite guard.
func TestOpsRestore_RefusesExistingDatabase(t *testing.T) {
	t.Setenv("NEBULA_MGMT_MASTER_KEY", "")
	master := masterKeyB64(3)

	srcDir := t.TempDir()
	srcCfg, _ := writeServerConfig(t, srcDir, master)
	if err := Init(srcCfg); err != nil {
		t.Fatalf("init source: %v", err)
	}
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := OpsBackup(srcCfg, archive, "", "vtest"); err != nil {
		t.Fatalf("OpsBackup: %v", err)
	}

	// Restoring back onto the live source DB without --force must refuse.
	if err := OpsRestore(srcCfg, archive, "", false); err == nil {
		t.Fatal("expected restore to refuse overwriting an existing database")
	}
	// With force it succeeds and moves the old DB aside.
	if err := OpsRestore(srcCfg, archive, "", true); err != nil {
		t.Fatalf("forced restore: %v", err)
	}
	if _, err := os.Stat(filepath.Join(srcDir, "nebula.db.pre-restore")); err != nil {
		t.Errorf("expected pre-restore backup of the old database: %v", err)
	}
}
