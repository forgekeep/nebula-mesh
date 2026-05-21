package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/juev/nebula-mesh/internal/config"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// OpsMintAdminKey opens the SQLite store referenced by configPath,
// looks up the admin operator by DefaultAdminUsername, mints a fresh
// operator_api_keys row with a SHA-256 hashed plaintext, records an
// audit entry, and prints the plaintext to stdout once. Used for
// break-glass recovery when the initial admin key is lost.
func OpsMintAdminKey(configPath string) error {
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	s, err := store.NewSQLiteStore(cfg.DBPath)
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
	h := sha256.Sum256([]byte(plaintext))

	entry := &models.OperatorAPIKey{
		ID:         uuid.NewString(),
		OperatorID: adminOp.ID,
		Name:       fmt.Sprintf("recovery-%s", time.Now().UTC().Format("20060102T150405Z")),
		KeyHash:    hex.EncodeToString(h[:]),
	}
	if err := s.CreateOperatorAPIKey(ctx, entry); err != nil {
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
