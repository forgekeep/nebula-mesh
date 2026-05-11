package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/juev/nebula-mesh/internal/config"
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

	// Ensure data directory
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Get passphrase for CA key (env var or interactive)
	passphrase, err := readCAPassphrase()
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	if passphrase == "" {
		return fmt.Errorf("passphrase cannot be empty")
	}

	// Create CA
	certPath := filepath.Join(cfg.DataDir, "ca.crt")
	keyPath := filepath.Join(cfg.DataDir, "ca.key")

	ca, _, err := pki.NewCA("nebula-mgmt CA", 365*24*time.Hour)
	if err != nil {
		return fmt.Errorf("create CA: %w", err)
	}

	if err := ca.Save(certPath, keyPath, passphrase); err != nil {
		return fmt.Errorf("save CA: %w", err)
	}

	fp, err := ca.CACertFingerprint()
	if err != nil {
		return fmt.Errorf("CA fingerprint: %w", err)
	}
	fmt.Printf("CA created: %s\n", certPath)
	fmt.Printf("CA fingerprint: %s\n", fp)

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
