package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/alerts"
	"github.com/forgekeep/nebula-mesh/internal/api"
	"github.com/forgekeep/nebula-mesh/internal/auth"
	"github.com/forgekeep/nebula-mesh/internal/caimport"
	"github.com/forgekeep/nebula-mesh/internal/cawatch"
	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/ratelimit"
	"github.com/forgekeep/nebula-mesh/internal/secretingress"
	"github.com/forgekeep/nebula-mesh/internal/store"
	"github.com/forgekeep/nebula-mesh/internal/web"
	"github.com/forgekeep/nebula-mesh/internal/webhook"
)

// buildMux assembles the top-level routing per issue #69.
//
//   - /api/                  → API server (admin REST API, agent endpoints)
//   - /healthz, /readyz      → API server (kept at root for monitoring scrapes)
//   - /metrics, /debug/      → API server (kept at root for Prometheus / pprof)
//   - /health                → API server (legacy alias)
//   - / (everything else)    → Web UI (which 302s "/" to "/ui/")
//
// API endpoints under /api/ that are not registered in api.Server return 404
// from the API surface (not from the UI router). Static assets and the
// favicon are still served by the UI handler.
func buildMux(webUI, apiSrv http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/api/", apiSrv)
	mux.Handle("/healthz", apiSrv)
	mux.Handle("/readyz", apiSrv)
	mux.Handle("/metrics", apiSrv)
	mux.Handle("/debug/", apiSrv)
	mux.Handle("/health", apiSrv) // legacy alias
	mux.Handle("/", webUI)
	return mux
}

// Serve starts the management server.
func Serve(configPath string, insecureHTTP bool) error {
	cfg, err := config.LoadServerConfig(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// The --insecure-http flag overrides the config field so the opt-out can
	// be expressed either way (#179).
	if insecureHTTP {
		cfg.AllowInsecureHTTP = true
	}
	// Fail fast before any DB/key work if we'd otherwise serve cleartext on a
	// routable address.
	if err := cfg.RequireSecureBind(); err != nil {
		return err
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

	// Warn if legacy api_key: field was detected in the YAML.
	if cfg.HasLegacyAPIKey() {
		logger.Warn("config field 'api_key' is deprecated and ignored; use 'nebula-mgmt ops mint-admin-key' to recover an admin key", "config", configPath)
	}

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
	// No API key is passed to serve-time seed — the initial key is generated
	// and printed during 'nebula-mgmt init'. This call is defensive: in most
	// cases the operator already exists from init; seed is a no-op.
	if seeded, err := SeedAdminOperator(migrateCtx, s, cfg.UIPassword, ""); err != nil {
		return fmt.Errorf("seed admin operator: %w", err)
	} else if seeded {
		logger.Info("seeded initial admin operator", "username", DefaultAdminUsername)
	}

	// Master keystore is REQUIRED
	masterB64 := cfg.MasterKey
	if env := os.Getenv("NEBULA_MGMT_MASTER_KEY"); env != "" {
		masterB64 = env
	}
	if masterB64 == "" {
		return fmt.Errorf("master key required: set NEBULA_MGMT_MASTER_KEY env or master_key in %s", configPath)
	}
	master, err := keystore.NewMasterFromBase64(masterB64)
	if err != nil {
		return fmt.Errorf("master key: %w", err)
	}
	caResolver := pki.NewCAResolver(s, master)

	// Validate: no rows should have empty ca_id from migration era.
	empty, err := s.CountEmptyCAIDRows(migrateCtx)
	if err != nil {
		return fmt.Errorf("validate ca_id backfill: %w", err)
	}
	if empty > 0 {
		return fmt.Errorf("found %d rows with empty ca_id; legacy migration required (see ADR-0007)", empty)
	}

	// Create API server
	apiSrv := api.NewServer(s, logger)
	apiSrv.WithMetricsEnabled(cfg.Metrics.PrometheusEnabled())
	apiSrv.WithMetricsRequireAuth(cfg.Metrics.RequireAuthEnabled())
	apiSrv.WithEnrollmentTokenTTL(cfg.EnrollmentTokenTTLDuration())

	// Outbound lifecycle-event webhooks (#256). When enabled, handlers emit
	// host.enrolled/blocked/unblocked/deleted and cert.rotated through the
	// dispatcher; cert.expiring is fanned in below via the alerts scanner. Nil
	// when disabled — the api emitter and Close are both nil-safe.
	// The webhook dispatcher always runs: managed subscriptions (#256 phase 2)
	// are created at runtime via the API, so the bus must be live to pick them
	// up even when the static config webhook (phase 1) is unset. It fans each
	// event out to DB-backed subscriptions plus the optional static config
	// target.
	webhookDispatcher := webhook.New(webhook.Config{
		URL:          cfg.Webhooks.URL,
		HMACSecret:   cfg.Webhooks.HMACSecret,
		AllowPrivate: cfg.Webhooks.AllowPrivate,
		Events:       cfg.Webhooks.Events,
		Source:       webhook.NewStoreSource(s, master, logger),
	}, logger)
	defer webhookDispatcher.Close()
	apiSrv.WithEventEmitter(webhookDispatcher)
	logger.Info("webhook dispatcher started", "static_url", cfg.Webhooks.URL != "")

	// Build a single rate limiter shared by API and Web. The Web UI runs
	// auth/ui groups; the API server runs api/enroll/agent_poll groups.
	trustedProxyPrefixes, err := cfg.RateLimit.TrustedProxyPrefixes()
	if err != nil {
		return err
	}
	rlCfg := ratelimit.Default()
	rlCfg.Enabled = cfg.RateLimit.IsEnabled()
	rlCfg.TrustProxyHeader = cfg.RateLimit.TrustProxyHeader
	rlCfg.TrustedProxyPrefixes = trustedProxyPrefixes
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
	apiSrv.WithCAResolver(caResolver)
	caImportLimits := caimport.DefaultLimits()
	if cfg.CAImport.MaxArgon2MemoryKiB != 0 {
		caImportLimits.MaxArgon2MemoryKiB = cfg.CAImport.MaxArgon2MemoryKiB
	}
	if cfg.CAImport.MaxArgon2Iterations != 0 {
		caImportLimits.MaxArgon2Iterations = cfg.CAImport.MaxArgon2Iterations
	}
	if cfg.CAImport.MaxArgon2Parallelism != 0 {
		caImportLimits.MaxArgon2Parallelism = cfg.CAImport.MaxArgon2Parallelism
	}
	secretIngressPolicy := secretingress.NewPolicy(cfg.Listen, cfg.TrustedSecretIngressProxy)
	sharedCAImporter := caimport.NewService(s, master, caImportLimits)
	apiSrv.WithCAImportLimits(caImportLimits)
	apiSrv.WithSecretIngressPolicy(secretIngressPolicy)
	apiSrv.WithMaster(master)
	apiSrv.WithCAImporter(sharedCAImporter)

	// Safety net: ensure admin operator has a default CA (idempotent).
	adminOp, err := s.GetOperatorByUsername(migrateCtx, DefaultAdminUsername)
	if err == nil {
		ca, minted, err := pki.MintAndStoreCA(migrateCtx, s, master, logger,
			pki.MintRequest{
				Operator:     adminOp,
				Name:         DefaultAdminUsername + "-default",
				Duration:     10 * 365 * 24 * time.Hour,
				SkipIfActive: true,
			})
		if err != nil {
			logger.Error("provision admin CA", "error", err)
		} else if minted {
			logger.Info("provisioned admin default CA",
				"name", ca.Name, "fingerprint", ca.Fingerprint)
		}
		if ca != nil {
			apiSrv.WithDefaultCAID(ca.ID)
		}
	}

	// Create Web UI
	webUI, err := web.New(s, logger)
	if err != nil {
		return fmt.Errorf("init web UI: %w", err)
	}
	webUI.WithLifecycleEventEmitter(webhookDispatcher)
	webUI.AllowSelfRegistration(cfg.AllowSelfRegistration)
	webUI.WithLoginRecorder(apiSrv.RecordLogin)
	webUI.WithRateLimiter(limiter)
	webUI.WithPasswordPolicy(pwPolicy)
	webUI.WithCAImportLimits(caImportLimits)
	webUI.WithSecretIngressPolicy(secretIngressPolicy)
	webUI.WithMaster(master)
	webUI.WithCAImporter(sharedCAImporter)
	webUI.WithCAResolver(caResolver)
	webUI.WithEnrollmentTokenTTL(cfg.EnrollmentTokenTTLDuration())

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
		// Surface the relaxed-posture deployment in startup logs so the
		// operator-of-operator sees that email_verified is being skipped.
		// Silent bypass is a real risk: a hostile or coerced deployer
		// could flip the bit, register an unverified-email account at a
		// permitted domain on a hostile IdP, and log in as a legitimate
		// operator. Matches dex's `insecureSkipEmailVerified` posture
		// (logs loudly when relaxed).
		if !cfg.OIDC.EmailVerifiedRequired() {
			logger.Warn("oidc email_verified check disabled",
				"oidc_issuer", cfg.OIDC.Issuer,
				"hint", "set oidc.require_email_verified: true (default) to re-enable")
		}
	}

	// Resolve cookie_secure AFTER any OIDC wiring so the OIDC state cookie
	// picks up the same flag (the helper propagates to both session manager
	// and OIDC). Closes GHSA-rqfj-vv8r-xhqc.
	webUI.WithCookieSecure(cfg.CookieSecureResolved())

	mux := buildMux(webUI, apiSrv)

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           securityHeaders(mux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
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
				URL:          cfg.Alerts.WebhookURL,
				HMACSecret:   cfg.Alerts.WebhookHMACSecret,
				AllowPrivate: cfg.Alerts.AllowPrivateWebhook,
			})
		}
		// Fold cert.expiring into the unified webhook bus when configured, so it
		// is delivered alongside the handler-driven events under one signing
		// secret and event-type filter.
		if webhookDispatcher != nil {
			sinks = append(sinks, certExpiryWebhookSink{webhookDispatcher})
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

	// CA auto-rotation scanner — periodically finds CAs approaching expiry
	// and rotates them. Disabled by default; opt in via the `ca_auto_rotate`
	// block in server config (issue #110).
	if cfg.CAAutoRotate.Enabled {
		if master == nil {
			logger.Warn("ca_auto_rotate enabled but master key not configured; auto-rotate disabled")
		} else {
			threshold := cfg.CAAutoRotate.Threshold
			if threshold <= 0 {
				threshold = 0.20
			}
			interval := cfg.CAAutoRotate.Interval
			if interval <= 0 {
				interval = 6 * time.Hour
			}
			caScanner := &cawatch.Scanner{
				Store:     s,
				Master:    master,
				Logger:    logger,
				Threshold: threshold,
				Interval:  interval,
			}
			go caScanner.StartLoop(ctx)
			logger.Info("ca auto-rotate scanner enabled",
				"interval", interval,
				"threshold", threshold,
			)
		}
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
