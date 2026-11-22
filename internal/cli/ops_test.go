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

	// Refuse piped output before minting, then deliver to an exclusive file.
	r, w, err := os.Pipe()
	require.NoError(t, err)
	oldStdout := os.Stdout
	os.Stdout = w
	err = OpsMintAdminKey(configPath, "")
	os.Stdout = oldStdout
	require.NoError(t, w.Close())
	require.NoError(t, r.Close())
	require.ErrorContains(t, err, "standard output is not a terminal")
	before, err := s.ListOperatorAPIKeys(ctx, adminOp.ID)
	require.NoError(t, err)
	require.Len(t, before, 1)

	private := filepath.Join(tmpDir, "private")
	require.NoError(t, os.Mkdir(private, 0o700))
	shared := filepath.Join(tmpDir, "shared")
	require.NoError(t, os.Mkdir(shared, 0o700))
	require.NoError(t, os.Chmod(shared, 0o755))
	require.ErrorContains(t, OpsMintAdminKey(configPath, filepath.Join(shared, "admin.key")), "private (0700)")
	output := filepath.Join(private, "admin.key")
	require.NoError(t, OpsMintAdminKey(configPath, output))
	bits, err := os.Stat(output)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), bits.Mode().Perm())
	data, err := os.ReadFile(output)
	require.NoError(t, err)
	plaintextKey := strings.TrimSpace(string(data))
	require.Len(t, plaintextKey, 64)
	require.Error(t, OpsMintAdminKey(configPath, output))
	after, err := os.ReadFile(output)
	require.NoError(t, err)
	require.True(t, string(after) == string(data), "existing output was changed")

	// Verify DB state: new key created for admin
	keys, err := s.ListOperatorAPIKeys(ctx, adminOp.ID)
	require.NoError(t, err)
	require.Len(t, keys, 2, "expected exactly two keys (initial + recovery)")

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

	master, hasher, err := loadRuntimeKeys(masterB64)
	require.NoError(t, err)
	t.Cleanup(hasher.Destroy)
	s, err := store.NewSQLiteStore(dbPath, store.WithCredentialHasher(hasher), store.WithTOTPSecretMaster(master))
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
	errResult := OpsMintAdminKey(configPath, filepath.Join(tmpDir, "admin.key"))

	// Verify error is not nil and contains readable message
	require.Error(t, errResult)
	require.True(t, strings.Contains(errResult.Error(), DefaultAdminUsername) ||
		strings.Contains(errResult.Error(), "admin") ||
		strings.Contains(errResult.Error(), "not found"),
		"error message should mention admin or 'not found'. Got: %v", errResult)
}

func TestOpsMintAdminKey_InvalidConfig(t *testing.T) {
	// Call with non-existent config path
	errResult := OpsMintAdminKey(filepath.Join(t.TempDir(), "missing.yml"), "unused")

	// Verify error is not nil
	require.Error(t, errResult)
	// Error should be readable (not panic)
	require.NotContains(t, errResult.Error(), "panic")
}
