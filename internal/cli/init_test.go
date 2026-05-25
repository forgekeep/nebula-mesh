package cli

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/store"
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

	// Assert that admin operator has exactly 1 API key with the correct name
	keys, err := s.ListOperatorAPIKeys(ctx, adminOp.ID)
	if err != nil {
		t.Fatalf("list admin API keys: %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("expected admin to have 1 API key, got %d", len(keys))
	}
	if len(keys) > 0 && keys[0].Name != "initial-admin-key" {
		t.Errorf("expected API key name 'initial-admin-key', got %q", keys[0].Name)
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

func TestInit_PrintsAdminAPIKeyOnce(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid base64 master key (32 bytes)
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i % 256)
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterKey)

	// Set master key via env
	t.Setenv("NEBULA_MGMT_MASTER_KEY", masterB64)

	// Create config WITHOUT api_key and WITHOUT ui_password
	// (to test that init generates and prints fresh plaintext)
	cfgPath := filepath.Join(tmpDir, "server.yaml")
	dbPath := filepath.Join(tmpDir, "nebula.db")
	cfgContent := `listen: ":8080"
data_dir: "` + tmpDir + `"
db_path: "` + dbPath + `"
log_level: "info"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// Capture stdout
	rOut, wOut, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = wOut

	err := Init(cfgPath)

	wOut.Close()
	os.Stdout = oldStdout
	output, _ := io.ReadAll(rOut)

	require.NoError(t, err)

	outputStr := string(output)
	t.Logf("Init stdout:\n%s", outputStr)

	// Assert: stdout contains the "capture now" block
	assert.Contains(t, outputStr, "Admin API key (capture now, will not be shown again)", "stdout should contain admin key message")

	// Extract the printed key from the output (between the delimiters)
	lines := strings.Split(outputStr, "\n")
	var printedKey string
	for i, line := range lines {
		if strings.Contains(line, "Admin API key") {
			// Next line should be the key
			if i+1 < len(lines) {
				printedKey = strings.TrimSpace(lines[i+1])
				break
			}
		}
	}
	require.NotEmpty(t, printedKey, "should have extracted printed API key from stdout")

	// Verify printed key is 64-char hex (32 bytes)
	assert.Len(t, printedKey, 64, "API key should be 64 hex characters")
	_, err = hex.DecodeString(printedKey)
	require.NoError(t, err, "printed key should be valid hex")

	// Assert: config file does NOT contain api_key after init
	configBytes, err := os.ReadFile(cfgPath)
	require.NoError(t, err, "should read config file")
	assert.NotContains(t, string(configBytes), "api_key:", "config file should not contain 'api_key:' field")

	// Assert: admin operator exists in DB with exactly 1 API key
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s, err := store.NewSQLiteStore(dbPath)
	require.NoError(t, err, "open store")
	defer s.Close()

	adminOp, err := s.GetOperatorByUsername(ctx, DefaultAdminUsername)
	require.NoError(t, err, "get admin operator")

	keys, err := s.ListOperatorAPIKeys(ctx, adminOp.ID)
	require.NoError(t, err, "list admin's API keys")

	assert.Len(t, keys, 1, "admin should have exactly 1 API key")
	if len(keys) > 0 {
		assert.Equal(t, "initial-admin-key", keys[0].Name, "first admin key should be named 'initial-admin-key'")
	}
}
