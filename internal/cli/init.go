package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// Init initializes the management server: creates CA, generates API key, and initializes the database.
// configPath is required — the generated API key is written back to this file.
func Init(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("--config is required")
	}

	cfg, err := loadOrCreateConfig(configPath)
	if err != nil {
		return err
	}

	// Ensure data directory. 0o750 — contains the SQLite DB and CA material
	// (per ADR 0002 encrypted DEKs alongside the legacy CA files); no need
	// for other local users to traverse.
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Master key is REQUIRED
	masterB64 := cfg.MasterKey
	if env := os.Getenv("NEBULA_MGMT_MASTER_KEY"); env != "" {
		masterB64 = env
	}
	if masterB64 == "" {
		return fmt.Errorf("master key required: set NEBULA_MGMT_MASTER_KEY env or master_key in %s", configPath)
	}
	master, err := keystore.NewMasterFromBase64(masterB64)
	if err != nil {
		return fmt.Errorf("parse master key: %w", err)
	}

	// Generate admin API key plaintext (32 random bytes).
	// This key is NOT saved to the config file; it is printed once to stdout
	// and passed directly to SeedAdminOperator for immediate seeding in the DB.
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate API key: %w", err)
	}
	plaintext := hex.EncodeToString(keyBytes)

	// Initialize database
	s, err := store.NewSQLiteStore(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			slog.Error("close store", "error", err)
		}
	}()

	migrateCtx, migrateCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer migrateCancel()
	if err := s.Migrate(migrateCtx); err != nil {
		return fmt.Errorf("migrate database: %w", err)
	}

	// Seed admin operator with the generated plaintext key.
	// If ui_password is empty, the seed operation is a no-op (no admin password).
	// This is intentional: an admin with no UI password cannot log in via the web UI,
	// and may use API keys for programmatic access, or rely on external auth (e.g., OIDC).
	if seeded, err := SeedAdminOperator(migrateCtx, s, cfg.UIPassword, plaintext); err != nil {
		return fmt.Errorf("seed admin operator: %w", err)
	} else if seeded {
		// Print the generated admin API key with a prominent notice.
		fmt.Println()
		fmt.Println("=== Admin API key (capture now, will not be shown again) ===")
		fmt.Println(plaintext)
		fmt.Println("=================================================")
		fmt.Println()
	}

	// Mint admin default CA
	adminOp, err := s.GetOperatorByUsername(migrateCtx, DefaultAdminUsername)
	if err != nil {
		return fmt.Errorf("get admin operator: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, minted, err := pki.MintAndStoreCA(migrateCtx, s, master, logger,
		pki.MintRequest{
			Operator:     adminOp,
			Name:         DefaultAdminUsername + "-default",
			Duration:     10 * 365 * 24 * time.Hour,
			SkipIfActive: true,
		})
	if err != nil {
		return fmt.Errorf("provision admin CA: %w", err)
	}
	if minted {
		fmt.Printf("Admin default CA provisioned: %s (fingerprint: %s)\n",
			ca.Name, ca.Fingerprint)
	}

	fmt.Printf("Database initialized: %s\n", cfg.DBPath)
	fmt.Println("Initialization complete.")
	return nil
}

// loadOrCreateConfig loads an existing config or creates a new one with defaults
// at path if the file does not exist.
func loadOrCreateConfig(path string) (*config.ServerConfig, error) {
	if _, err := os.Stat(path); err == nil {
		return config.LoadServerConfig(path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat config: %w", err)
	}

	// Bind loopback by default (#179): a fresh install serves cleartext only to
	// the local host, so it is safe out of the box behind a TLS-terminating
	// proxy. For direct remote access set tls_cert+tls_key, or opt into
	// plaintext exposure with allow_insecure_http + a routable listen address.
	cfg := &config.ServerConfig{
		Listen:   "127.0.0.1:8080",
		DataDir:  "/var/lib/nebula-mgmt",
		DBPath:   "/var/lib/nebula-mgmt/nebula.db",
		LogLevel: "info",
	}
	if err := config.SaveServerConfig(path, cfg); err != nil {
		return nil, fmt.Errorf("create initial config: %w", err)
	}
	fmt.Printf("Created config: %s\n", path)
	return cfg, nil
}
