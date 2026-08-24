package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"
	"uuid"

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// OpsMintAdminKey opens the SQLite store referenced by configPath,
// looks up the admin operator by DefaultAdminUsername, mints a fresh
// operator_api_keys row with a keyed verifier, records an
// audit entry, and prints the plaintext to stdout once. Used for
// break-glass recovery when the initial admin key is lost.
func OpsMintAdminKey(configPath string) error {
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	masterB64 := cfg.MasterKey
	if env := os.Getenv("NEBULA_MGMT_MASTER_KEY"); env != "" {
		masterB64 = env
	}
	if masterB64 == "" {
		return fmt.Errorf("master key required: set NEBULA_MGMT_MASTER_KEY env or master_key in %s", configPath)
	}
	master, hasher, err := loadRuntimeKeys(masterB64)
	if err != nil {
		return fmt.Errorf("parse master key: %w", err)
	}
	defer hasher.Destroy()

	s, err := store.NewSQLiteStore(cfg.DBPath,
		store.WithCredentialHasher(hasher),
		store.WithCredentialCutoverGuard(credentialCutoverMasterGuard(master)),
	)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() {
		if cerr := s.Close(); cerr != nil {
			slog.Error("close store", "error", cerr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	adminOp, err := s.GetOperatorByUsername(ctx, DefaultAdminUsername)
	if err != nil {
		return fmt.Errorf("admin operator '%s' not found in database — run 'nebula-mgmt init' first: %w", DefaultAdminUsername, err)
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	plaintext := hex.EncodeToString(keyBytes)

	entry := &models.OperatorAPIKey{
		ID:         uuid.NewV4().String(),
		OperatorID: adminOp.ID,
		Name:       fmt.Sprintf("recovery-%s", time.Now().UTC().Format("20060102T150405Z")),
	}
	if err := s.CreateOperatorAPIKey(ctx, entry, plaintext); err != nil {
		return fmt.Errorf("create api key: %w", err)
	}
	if err := s.AddAuditEntry(ctx, "ops-cli-recovery", "operator.api_key.create", adminOp.ID, entry.ID); err != nil {
		slog.Warn("failed to record audit entry", "error", err)
	}

	fmt.Println()
	fmt.Println("=== Admin API key (capture now, will not be shown again) ===")
	fmt.Println(plaintext)
	fmt.Println("=================================================")
	fmt.Println()
	return nil
}

// OpsResetTOTP performs a local, explicitly confirmed break-glass reset. It
// preserves the operator's enabled/disabled status while revoking sessions and
// deleting recovery codes atomically with the audit record.
func OpsResetTOTP(configPath, username string, confirm bool) error {
	if configPath == "" {
		return fmt.Errorf("--config is required")
	}
	if username == "" {
		return fmt.Errorf("--username is required")
	}
	if !confirm {
		return fmt.Errorf("--confirm is required: this disables TOTP and revokes all sessions for %q", username)
	}

	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	masterB64 := cfg.MasterKey
	if env := os.Getenv("NEBULA_MGMT_MASTER_KEY"); env != "" {
		masterB64 = env
	}
	if masterB64 == "" {
		return fmt.Errorf("master key required: set NEBULA_MGMT_MASTER_KEY env or master_key in %s", configPath)
	}
	master, hasher, err := loadRuntimeKeys(masterB64)
	if err != nil {
		return fmt.Errorf("parse master key: %w", err)
	}
	defer hasher.Destroy()

	s, err := store.NewSQLiteStore(cfg.DBPath,
		store.WithCredentialHasher(hasher),
		store.WithCredentialCutoverGuard(credentialCutoverMasterGuard(master)),
	)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			slog.Error("close store", "error", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}
	if err := s.ResetOperatorTOTPBreakGlass(ctx, username); err != nil {
		return fmt.Errorf("reset TOTP for %q: %w", username, err)
	}
	fmt.Printf("TOTP disabled and sessions revoked for %s; operator status was not changed\n", username)
	return nil
}
