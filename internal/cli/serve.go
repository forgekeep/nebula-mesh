package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/juev/nebula-mesh/internal/api"
	"github.com/juev/nebula-mesh/internal/config"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
	"github.com/juev/nebula-mesh/internal/web"
	"golang.org/x/term"
)

// Serve starts the management server.
func Serve(configPath string) error {
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Setup logger
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Load CA
	certPath := filepath.Join(cfg.DataDir, "ca.crt")
	keyPath := filepath.Join(cfg.DataDir, "ca.key")

	fmt.Print("Enter CA passphrase: ")
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	ca, err := pki.LoadCA(certPath, keyPath, string(passBytes))
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	fp, err := ca.CACertFingerprint()
	if err != nil {
		return fmt.Errorf("CA fingerprint: %w", err)
	}
	logger.Info("CA loaded", "fingerprint", fp)

	// Open database
	s, err := store.NewSQLiteStore(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			logger.Error("close store", "error", err)
		}
	}()

	if err := s.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// Create API server
	apiSrv := api.NewServer(s, ca, cfg.APIKey, logger, api.CAConfig{
		CertPath:   certPath,
		KeyPath:    keyPath,
		Passphrase: string(passBytes),
	})

	// Create Web UI
	uiPassword := cfg.UIPassword
	if uiPassword == "" {
		uiPassword = cfg.APIKey // fallback to API key as password
	}
	webUI, err := web.New(s, uiPassword, logger)
	if err != nil {
		return fmt.Errorf("init web UI: %w", err)
	}

	// Combine: Web UI + API
	mux := http.NewServeMux()
	mux.Handle("/ui/", webUI)
	mux.Handle("/static/", webUI)
	mux.Handle("/", apiSrv)

	httpServer := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
	}()

	logger.Info("server starting", "listen", cfg.Listen)
	if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	<-ctx.Done()
	return nil
}
