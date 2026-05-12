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
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
	"github.com/juev/nebula-mesh/internal/web"
	"golang.org/x/term"
)

// caPassphraseEnv is read by readCAPassphrase before falling back to TTY prompt.
const caPassphraseEnv = "NEBULA_MGMT_CA_PASSPHRASE"

// readCAPassphrase reads the CA passphrase from $NEBULA_MGMT_CA_PASSPHRASE if set,
// otherwise prompts on the controlling terminal. Returns an error when stdin
// is not a TTY and the env var is not set (typical of systemd / Docker without -i).
func readCAPassphrase() (string, error) {
	if v, ok := os.LookupEnv(caPassphraseEnv); ok {
		if v == "" {
			return "", fmt.Errorf("%s is set but empty", caPassphraseEnv)
		}
		return v, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("stdin is not a TTY and %s is unset — cannot read CA passphrase", caPassphraseEnv)
	}
	fmt.Print("Enter CA passphrase: ")
	passBytes, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(passBytes), nil
}

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

	passphrase, err := readCAPassphrase()
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}

	ca, err := pki.LoadCA(certPath, keyPath, passphrase)
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

	migrateCtx, migrateCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer migrateCancel()
	if err := s.Migrate(migrateCtx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// Seed an admin operator if the operators table is still empty (idempotent).
	uiPassword := cfg.UIPassword
	if uiPassword == "" {
		uiPassword = cfg.APIKey
	}
	if seeded, err := SeedAdminOperator(migrateCtx, s, uiPassword, cfg.APIKey); err != nil {
		return fmt.Errorf("seed admin operator: %w", err)
	} else if seeded {
		logger.Info("seeded initial admin operator", "username", DefaultAdminUsername)
	}

	// Master keystore (optional but required for per-operator CAs)
	masterB64 := cfg.MasterKey
	if env := os.Getenv("NEBULA_MGMT_MASTER_KEY"); env != "" {
		masterB64 = env
	}
	var (
		master      *keystore.Master
		caResolver  *pki.CAResolver
		defaultCAID string
	)
	if masterB64 != "" {
		master, err = keystore.NewMasterFromBase64(masterB64)
		if err != nil {
			return fmt.Errorf("master key: %w", err)
		}
		caResolver = pki.NewCAResolver(s, master)

		// Import legacy on-disk CA into the cas table on first start.
		adminOp, lookupErr := s.GetOperatorByUsername(migrateCtx, DefaultAdminUsername)
		if lookupErr == nil {
			defaultCAID, _, err = ImportLegacyCAIfNeeded(
				migrateCtx, s, master, certPath, keyPath, passphrase, adminOp.ID,
			)
			if err != nil {
				return fmt.Errorf("import legacy CA: %w", err)
			}
		}
	} else {
		logger.Warn("NEBULA_MGMT_MASTER_KEY is unset; per-operator CAs are disabled and existing single-CA flows continue to work")
	}

	// Create API server
	apiSrv := api.NewServer(s, ca, cfg.APIKey, logger, api.CAConfig{
		CertPath:   certPath,
		KeyPath:    keyPath,
		Passphrase: passphrase,
	})
	if caResolver != nil {
		apiSrv.WithCAResolver(caResolver)
		apiSrv.WithMaster(master)
		apiSrv.WithDefaultCAID(defaultCAID)
	}

	// Create Web UI
	webUI, err := web.New(s, logger)
	if err != nil {
		return fmt.Errorf("init web UI: %w", err)
	}
	webUI.AllowSelfRegistration(cfg.AllowSelfRegistration)

	// Optional OIDC integration
	if cfg.OIDC != nil && cfg.OIDC.Enabled {
		oidcCtx, oidcCancel := context.WithTimeout(context.Background(), 10*time.Second)
		oidcProvider, err := web.NewOIDC(oidcCtx, cfg.OIDC, s, webUI.Session(), logger)
		oidcCancel()
		if err != nil {
			return fmt.Errorf("init oidc: %w", err)
		}
		webUI.WithOIDC(oidcProvider)
		logger.Info("oidc enabled", "issuer", cfg.OIDC.Issuer)
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

	// Start session cleanup (stops on ctx cancel)
	webUI.StartSessionCleanup(ctx)

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

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		logger.Info("server starting (TLS)", "listen", cfg.Listen, "cert", cfg.TLSCert)
		if err := httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	} else {
		logger.Warn("server starting WITHOUT TLS — recommended only behind a TLS-terminating proxy", "listen", cfg.Listen)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	}

	<-ctx.Done()
	return nil
}
