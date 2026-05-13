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

	"github.com/juev/nebula-mesh/internal/alerts"
	"github.com/juev/nebula-mesh/internal/api"
	"github.com/juev/nebula-mesh/internal/auth"
	"github.com/juev/nebula-mesh/internal/config"
	"github.com/juev/nebula-mesh/internal/ratelimit"
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
	apiSrv.WithMetricsEnabled(cfg.Metrics.PrometheusEnabled())

	// Build a single rate limiter shared by API and Web. The Web UI runs
	// auth/ui groups; the API server runs api/enroll/agent_poll groups.
	rlCfg := ratelimit.Default()
	rlCfg.Enabled = cfg.RateLimit.IsEnabled()
	rlCfg.TrustProxyHeader = cfg.RateLimit.TrustProxyHeader
	for name, gc := range cfg.RateLimit.Groups {
		if gc.Rate > 0 && gc.Burst > 0 {
			rlCfg.Groups[name] = ratelimit.GroupConfig{Rate: gc.Rate, Burst: gc.Burst}
		}
	}
	limiter := ratelimit.New(rlCfg)
	apiSrv.WithRateLimiter(limiter)

	// Password policy — defaults from auth.Default(), overridden per field
	// when the server config opts in.
	pwPolicy := auth.Default()
	if v := cfg.Password.MinLength; v != nil {
		pwPolicy.MinLength = *v
	}
	if v := cfg.Password.RequireClasses; v != nil {
		pwPolicy.RequireClasses = *v
	}
	if v := cfg.Password.BlockCommon; v != nil {
		pwPolicy.BlockCommon = *v
	}
	if v := cfg.Password.BlockUsername; v != nil {
		pwPolicy.BlockUsername = *v
	}
	apiSrv.WithPasswordPolicy(pwPolicy)

	// Persist enforce_2fa from server.yml into server_settings so the gate
	// reads the same row admins will edit from the future Settings UI.
	if cfg.EnforceTOTP != nil {
		val := "false"
		if *cfg.EnforceTOTP {
			val = "true"
		}
		if err := s.SetServerSetting(context.Background(), "enforce_2fa", val); err != nil {
			logger.Error("persist enforce_2fa setting", "error", err)
		}
	}
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
	webUI.WithLoginRecorder(apiSrv.RecordLogin)
	webUI.WithRateLimiter(limiter)
	webUI.WithPasswordPolicy(pwPolicy)
	if master != nil {
		webUI.WithMaster(master)
	}

	// Live host-status SSE: API server fires HostSeenEmitter on each agent
	// poll, EventBus fans out to subscribed browser tabs.
	eventBus := web.NewEventBus()
	webUI.WithEventBus(eventBus)
	apiSrv.WithHostSeenEmitter(func(hostID string, lastSeen time.Time, networkID string) {
		eventBus.Publish(web.HostSeenEvent{
			HostID:    hostID,
			LastSeen:  lastSeen,
			NetworkID: networkID,
		})
	})

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

	// Cert-expiry alerter — periodic scan that fans alerts out to audit log
	// and (optionally) a webhook. Disabled by default; opt in via the
	// `alerts` block in server config.
	if cfg.Alerts.Enabled {
		sinks := []alerts.Sink{&alerts.AuditSink{Store: s}}
		if cfg.Alerts.WebhookURL != "" {
			sinks = append(sinks, &alerts.WebhookSink{
				URL:        cfg.Alerts.WebhookURL,
				HMACSecret: cfg.Alerts.WebhookHMACSecret,
			})
		}
		scanner := &alerts.Scanner{
			Store:     s,
			Threshold: cfg.Alerts.ThresholdDuration(),
			Interval:  cfg.Alerts.IntervalDuration(),
			Sinks:     sinks,
			Logger:    logger,
		}
		go scanner.StartLoop(ctx)
		logger.Info("cert-expiry alerter enabled",
			"interval", scanner.Interval,
			"threshold", scanner.Threshold,
			"webhook", cfg.Alerts.WebhookURL != "",
		)
	}

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
