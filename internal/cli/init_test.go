package cli

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/juev/nebula-mesh/internal/store"
)

func TestInit_RejectsWithoutMaster(t *testing.T) {
	tmpDir := t.TempDir()

	// Clear NEBULA_MGMT_MASTER_KEY env if set
	t.Setenv("NEBULA_MGMT_MASTER_KEY", "")

	// Create config with empty master_key
	cfgPath := filepath.Join(tmpDir, "server.yaml")
	cfgContent := `listen: ":8080"
data_dir: "` + tmpDir + `"
db_path: "` + filepath.Join(tmpDir, "nebula.db") + `"
api_key: "test-key"
log_level: "info"
master_key: ""
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Try to init without master key
	err := Init(cfgPath)
	if err == nil {
		t.Fatal("expected error without master key, got nil")
		return
	}

	errMsg := err.Error()
	if errMsg == "" || !contains(errMsg, "master key required") {
		t.Errorf("error does not contain 'master key required': %v", err)
	}
}

func TestInit_AcceptsWithMasterEnv(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid base64 master key (32 bytes)
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i % 256)
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterKey)

	// Set master key via env
	t.Setenv("NEBULA_MGMT_MASTER_KEY", masterB64)

	// Create config without master_key
	cfgPath := filepath.Join(tmpDir, "server.yaml")
	cfgContent := `listen: ":8080"
data_dir: "` + tmpDir + `"
db_path: "` + filepath.Join(tmpDir, "nebula.db") + `"
api_key: "test-key"
log_level: "info"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Try to init with master key from env — should succeed
	err := Init(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error with master key env: %v", err)
	}
}

func TestInit_MintsAdminDefaultCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid base64 master key (32 bytes)
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i % 256)
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterKey)

	// Set master key via env
	t.Setenv("NEBULA_MGMT_MASTER_KEY", masterB64)

	// Create config
	cfgPath := filepath.Join(tmpDir, "server.yaml")
	dbPath := filepath.Join(tmpDir, "nebula.db")
	cfgContent := `listen: ":8080"
data_dir: "` + tmpDir + `"
db_path: "` + dbPath + `"
api_key: "test-key"
log_level: "info"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Initialize
	err := Init(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify admin default CA was minted
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()

	adminOp, err := s.GetOperatorByUsername(ctx, DefaultAdminUsername)
	if err != nil {
		t.Fatalf("get admin operator: %v", err)
	}

	cas, err := s.ListCAsByOwner(ctx, adminOp.ID)
	if err != nil {
		t.Fatalf("list cas: %v", err)
	}

	if len(cas) != 1 {
		t.Errorf("expected 1 CA, got %d", len(cas))
	}
	if cas[0].Name != "admin-default" {
		t.Errorf("expected CA name 'admin-default', got %q", cas[0].Name)
	}
	if cas[0].OwnerOperatorID != adminOp.ID {
		t.Errorf("expected owner %q, got %q", adminOp.ID, cas[0].OwnerOperatorID)
	}
}

func TestInit_DoesNotCreateOnDiskCA(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid base64 master key (32 bytes)
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i % 256)
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterKey)

	// Set master key via env
	t.Setenv("NEBULA_MGMT_MASTER_KEY", masterB64)

	// Create config
	cfgPath := filepath.Join(tmpDir, "server.yaml")
	cfgContent := `listen: ":8080"
data_dir: "` + tmpDir + `"
db_path: "` + filepath.Join(tmpDir, "nebula.db") + `"
api_key: "test-key"
log_level: "info"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Initialize
	err := Init(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify on-disk CA files don't exist
	caPath := filepath.Join(tmpDir, "ca.crt")
	keyPath := filepath.Join(tmpDir, "ca.key")

	if _, err := os.Stat(caPath); !os.IsNotExist(err) {
		t.Errorf("expected ca.crt to not exist, but stat returned: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Errorf("expected ca.key to not exist, but stat returned: %v", err)
	}
}

func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
