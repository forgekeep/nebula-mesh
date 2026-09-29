package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestVerifyRestoredCAs_SEC_SECRET_001WipesEveryLoadedManager(t *testing.T) {
	manager1, err := pki.NewCA("first", 0)
	if err != nil {
		t.Fatal(err)
	}
	manager2, err := pki.NewCA("second", 0)
	if err != nil {
		t.Fatal(err)
	}
	key1, key2 := manager1.RawKey(), manager2.RawKey()
	loadCalls := 0
	loadErr := errors.New("simulated CA verification failure")

	err = verifyRestoredCAs(context.Background(), []*models.CA{
		{ID: "first", Name: "first"},
		{ID: "second", Name: "second"},
		{ID: "third", Name: "third"},
	}, "/restored/nebula.db", func(_ context.Context, id string) (*pki.CAManager, error) {
		loadCalls++
		switch id {
		case "first":
			return manager1, nil
		case "second":
			return manager2, loadErr
		default:
			t.Fatalf("unexpected load after failure: %s", id)
			return nil, nil
		}
	})
	if !errors.Is(err, loadErr) {
		t.Fatalf("verifyRestoredCAs error = %v, want wrapped load error", err)
	}
	if loadCalls != 2 {
		t.Fatalf("LoadByID calls = %d, want 2 before failure", loadCalls)
	}
	for name, key := range map[string][]byte{"first": key1, "second": key2} {
		for i, b := range key {
			if b != 0 {
				t.Fatalf("%s manager key byte %d remains after verification: %d", name, i, b)
			}
		}
	}
}

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

func TestOpsBackup_SEC_TOTP_001_RefusesPlainArchiveBeforeSeedMigration(t *testing.T) {
	t.Setenv("NEBULA_MGMT_MASTER_KEY", "")
	dir := t.TempDir()
	cfgPath, dbPath := writeServerConfig(t, dir, masterKeyB64(42))
	if err := Init(cfgPath); err != nil {
		t.Fatal(err)
	}
	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`DROP TRIGGER operator_totp_secret_insert`,
		`DROP TRIGGER operator_totp_secret_update`,
		`DELETE FROM schema_migrations WHERE name = '029_encrypt_operator_totp.up.sql'`,
		`UPDATE operators SET totp_secret = 'JBSWY3DPEHPK3PXP' WHERE username = 'admin'`,
	} {
		if _, err := s.DB().ExecContext(context.Background(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	plainArchive := filepath.Join(t.TempDir(), "plain.tar.gz")
	if err := OpsBackup(cfgPath, plainArchive, "", "vtest"); err == nil || !contains(err.Error(), "plaintext TOTP seed") {
		t.Fatalf("plain backup error = %v", err)
	}
	if _, err := os.Stat(plainArchive); !os.IsNotExist(err) {
		t.Fatalf("plain backup artifact exists or stat failed: %v", err)
	}
	protectedArchive := filepath.Join(t.TempDir(), "protected.tar.gz")
	if err := OpsBackup(cfgPath, protectedArchive, "test-backup-passphrase", "vtest"); err != nil {
		t.Fatalf("encrypted backup of legacy DB: %v", err)
	}
	restoreDir := t.TempDir()
	restoreCfg, restoreDB := writeServerConfig(t, restoreDir, masterKeyB64(42))
	if err := OpsRestore(restoreCfg, protectedArchive, "test-backup-passphrase", false); err != nil {
		t.Fatalf("restore and migrate legacy TOTP seed: %v", err)
	}
	master, hasher, err := loadRuntimeKeys(masterKeyB64(42))
	if err != nil {
		t.Fatal(err)
	}
	defer hasher.Destroy()
	restored, err := store.NewSQLiteStore(restoreDB, store.WithTOTPSecretMaster(master))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	op, err := restored.GetOperatorByUsername(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	if op.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatal("restored TOTP seed differs from the legacy value")
	}
	var stored string
	if err := restored.DB().QueryRow(`SELECT totp_secret FROM operators WHERE username = 'admin'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == op.TOTPSecret {
		t.Fatal("restored database still contains the legacy plaintext TOTP seed")
	}
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
