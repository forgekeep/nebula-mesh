package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/juev/nebula-mesh/internal/config"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
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

	// Generate API key if not set
	if cfg.APIKey == "" {
		keyBytes := make([]byte, 32)
		if _, err := rand.Read(keyBytes); err != nil {
			return fmt.Errorf("generate API key: %w", err)
		}
		cfg.APIKey = hex.EncodeToString(keyBytes)
		if err := config.SaveServerConfig(configPath, cfg); err != nil {
			return fmt.Errorf("save config with API key: %w", err)
		}
		fmt.Printf("API key: %s\n", cfg.APIKey)
		fmt.Printf("Saved to: %s\n", configPath)
	}

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

	uiPassword := cfg.UIPassword
	if uiPassword == "" {
		uiPassword = cfg.APIKey
	}
	if seeded, err := SeedAdminOperator(migrateCtx, s, uiPassword, cfg.APIKey); err != nil {
		return fmt.Errorf("seed admin operator: %w", err)
	} else if seeded {
		fmt.Printf("Admin operator created: %s (password = ui_password from config; api_key seeded as their key)\n", DefaultAdminUsername)
	}

	// Mint admin default CA
	adminOp, err := s.GetOperatorByUsername(migrateCtx, DefaultAdminUsername)
	if err != nil {
		return fmt.Errorf("get admin operator: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ca, minted, err := pki.MintAndStoreCA(migrateCtx, s, master, logger,
		pki.MintRequest{
			Operator: adminOp,
			Name:     DefaultAdminUsername + "-default",
			Duration: 10 * 365 * 24 * time.Hour,
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

	cfg := &config.ServerConfig{
		Listen:   ":8080",
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
