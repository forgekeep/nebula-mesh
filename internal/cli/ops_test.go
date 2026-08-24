package cli

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestOpsMintAdminKey_Success(t *testing.T) {
	// Setup temp config and DB
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yml")
	dbPath := filepath.Join(tmpDir, "test.db")

	// Generate valid base64 master key (32 bytes)
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i % 256)
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterKey)
	t.Setenv("NEBULA_MGMT_MASTER_KEY", masterB64)

	// Write config YAML
	cfgContent := `listen: ":8443"
data_dir: "` + tmpDir + `"
db_path: "` + dbPath + `"
log_level: "info"
`
	require.NoError(t, os.WriteFile(configPath, []byte(cfgContent), 0o644))

	// Create store and migrate
	s, err := openCLITestStore(t, dbPath)
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	require.NoError(t, s.Migrate(ctx))

	// Seed initial admin operator directly
	hash, err := bcrypt.GenerateFromPassword([]byte("test-password"), bcrypt.DefaultCost)
	require.NoError(t, err)

	adminOp := &models.Operator{
		ID:           uuid.NewV4().String(),
		Username:     DefaultAdminUsername,
		PasswordHash: string(hash),
		Role:         "admin",
	}
	adminKey := &models.OperatorAPIKey{
		ID:         uuid.NewV4().String(),
		OperatorID: adminOp.ID,
		Name:       "initial-admin-key",
		KeyHash:    "test-hash",
	}
	_, err = s.SeedInitialAdminOperator(ctx, adminOp, adminKey, "test-admin-key")
	require.NoError(t, err)

	// Capture stdout during OpsMintAdminKey
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	errResult := OpsMintAdminKey(configPath)

	w.Close()
	os.Stdout = oldStdout

	output := make([]byte, 1024)
	n, _ := r.Read(output)
	outputStr := string(output[:n])

	// Verify success
	require.NoError(t, errResult)

	// Verify stdout contains "Admin API key (capture now"
	require.True(t, strings.Contains(outputStr, "Admin API key (capture now"),
		"stdout missing 'Admin API key (capture now' marker. Got:\n%s", outputStr)

	// Extract plaintext from stdout (between "===" markers)
	lines := strings.Split(outputStr, "\n")
	var plaintextKey string
	for i, line := range lines {
		if strings.Contains(line, "Admin API key (capture now") && i+1 < len(lines) {
			plaintextKey = strings.TrimSpace(lines[i+1])
			break
		}
	}
	require.NotEmpty(t, plaintextKey, "failed to extract plaintext from stdout")
	require.Len(t, plaintextKey, 64, "plaintext should be 64-char hex (32 bytes)")

	// Verify DB state: new key created for admin
	keys, err := s.ListOperatorAPIKeys(ctx, adminOp.ID)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(keys), 2, "expected at least 2 keys (initial + recovery)")

	// Find the recovery key
	var recoveryKey *models.OperatorAPIKey
	for _, k := range keys {
		if strings.HasPrefix(k.Name, "recovery-") {
			recoveryKey = k
			break
		}
	}
	require.NotNil(t, recoveryKey, "recovery key not found in DB")

	// SEC-CREDENTIAL-001: verify the persisted value is the keyed verifier
	// derived from the configured master, not a plain SHA-256 digest.
	hasher, err := credentialhash.New(masterKey)
	require.NoError(t, err)
	t.Cleanup(hasher.Destroy)
	expectedHash, err := hasher.Digest(credentialhash.PurposeOperatorAPIKey, []byte(plaintextKey))
	require.NoError(t, err)
	require.Equal(t, expectedHash, recoveryKey.KeyHash,
		"credential verifier mismatch: computed=%s, db=%s", expectedHash, recoveryKey.KeyHash)
}

func TestOpsResetTOTP_SEC_CREDENTIAL_001_RequiresConfirmationAndResets(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "server.yml")
	dbPath := filepath.Join(tmpDir, "server.db")
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterKey)
	t.Setenv("NEBULA_MGMT_MASTER_KEY", masterB64)
	require.NoError(t, os.WriteFile(configPath, []byte(
		"db_path: \""+dbPath+"\"\ndata_dir: \""+tmpDir+"\"\n"), 0o600))

	_, hasher, err := loadRuntimeKeys(masterB64)
	require.NoError(t, err)
	t.Cleanup(hasher.Destroy)
	s, err := store.NewSQLiteStore(dbPath, store.WithCredentialHasher(hasher))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	require.NoError(t, s.Migrate(context.Background()))
	op := &models.Operator{
		ID: "reset-op", Username: "reset-admin", PasswordHash: "hash",
		Status: models.OperatorStatusActive, Role: models.OperatorRoleAdmin,
	}
	require.NoError(t, s.CreateOperator(context.Background(), op))
	require.NoError(t, s.SetOperatorTOTP(context.Background(), op.ID, "secret", true))

	err = OpsResetTOTP(configPath, op.Username, false)
	require.ErrorContains(t, err, "--confirm")
	got, err := s.GetOperator(context.Background(), op.ID)
	require.NoError(t, err)
	require.True(t, got.TOTPEnabled)

	require.NoError(t, OpsResetTOTP(configPath, op.Username, true))
	got, err = s.GetOperator(context.Background(), op.ID)
	require.NoError(t, err)
	require.False(t, got.TOTPEnabled)
	require.Empty(t, got.TOTPSecret)
}

func TestOpsMintAdminKey_NoAdmin(t *testing.T) {
	// Setup temp config and DB WITHOUT seeding admin
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yml")
	dbPath := filepath.Join(tmpDir, "test.db")

	// Generate valid base64 master key (32 bytes)
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i % 256)
	}
	masterB64 := base64.StdEncoding.EncodeToString(masterKey)
	t.Setenv("NEBULA_MGMT_MASTER_KEY", masterB64)

	// Write config YAML
	cfgContent := `listen: ":8443"
data_dir: "` + tmpDir + `"
db_path: "` + dbPath + `"
log_level: "info"
`
	require.NoError(t, os.WriteFile(configPath, []byte(cfgContent), 0o644))

	// Create store and migrate, but do NOT seed admin
	s, err := openCLITestStore(t, dbPath)
	require.NoError(t, err)
	defer s.Close()

	ctx := context.Background()
	require.NoError(t, s.Migrate(ctx))

	// Attempt to mint key for non-existent admin
	errResult := OpsMintAdminKey(configPath)

	// Verify error is not nil and contains readable message
	require.Error(t, errResult)
	require.True(t, strings.Contains(errResult.Error(), DefaultAdminUsername) ||
		strings.Contains(errResult.Error(), "admin") ||
		strings.Contains(errResult.Error(), "not found"),
		"error message should mention admin or 'not found'. Got: %v", errResult)
}

func TestOpsMintAdminKey_InvalidConfig(t *testing.T) {
	// Call with non-existent config path
	errResult := OpsMintAdminKey("/tmp/nonexistent-config-path-xyz.yml")

	// Verify error is not nil
	require.Error(t, errResult)
	// Error should be readable (not panic)
	require.NotContains(t, errResult.Error(), "panic")
}
