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
	"golang.org/x/term"
)

// Init initializes the management server: creates CA, generates API key, and initializes the database.
func Init(configPath string) error {
	cfg, err := loadOrCreateConfig(configPath)
	if err != nil {
		return err
	}

	// Ensure data directory
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Get passphrase for CA key
	fmt.Print("Enter passphrase for CA key: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	passphrase := string(passBytes)
	if passphrase == "" {
		return fmt.Errorf("passphrase cannot be empty")
	}

	// Create CA
	certPath := filepath.Join(cfg.DataDir, "ca.crt")
	keyPath := filepath.Join(cfg.DataDir, "ca.key")

	ca, _, err := pki.NewCA("nebula-mesh CA", 365*24*time.Hour)
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
		fmt.Printf("API key: %s\n", cfg.APIKey)
		fmt.Println("Save this API key — it won't be shown again.")
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

func loadOrCreateConfig(path string) (*config.ServerConfig, error) {
	if path != "" {
		return config.LoadServerConfig(path)
	}
	return &config.ServerConfig{
		Listen:   ":8080",
		DataDir:  "/var/lib/nebula-mgmt",
		DBPath:   "/var/lib/nebula-mgmt/nebula.db",
		LogLevel: "info",
	}, nil
}
