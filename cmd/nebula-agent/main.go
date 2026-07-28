package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/agent"
	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/version"
)

// Populated at build time via -ldflags (see .goreleaser.yml).
var (
	versionStr = "dev"
	commit     = "none"
	date       = "unknown"
)

const defaultConfigPath = "/etc/nebula-agent/agent.yml"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop() // release signal handler before any os.Exit to avoid gocritic exitAfterDefer.
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	// Dispatch subcommands first so the unified flag set does not need to
	// understand "enroll" / "run" as positional arguments. `enroll` is
	// first-class (#88) and does NOT warn; `run` is still a deprecated alias.
	if len(args) > 0 {
		switch args[0] {
		case "enroll":
			// First-class subcommand (#88). No deprecation warning — this
			// is now the recommended way to enroll a host.
			return runEnroll(ctx, args[1:], stdout, stderr)
		case "run":
			_, _ = fmt.Fprintln(stderr, "warning: `nebula-agent run` is deprecated; invoke `nebula-agent` without a subcommand")
			return runLegacyRun(ctx, args[1:], stderr)
		case "service":
			return runService(ctx, args[1:], stdout, stderr)
		case "version", "--version", "-v":
			version.Print(stdout, "nebula-agent", versionStr, commit, date)
			return nil
		case "-h", "--help", "help":
			printUsage(stderr)
			return nil
		}
	}

	return runUnified(ctx, args, stderr)
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: nebula-agent [--config PATH] [--token-file PATH --server URL] [--nebula-config-path PATH] [--yes] [--force]")
	_, _ = fmt.Fprintln(w, "       nebula-agent enroll --server URL --token-file PATH [--nebula-config-path PATH] [--yes] [--force]")
	_, _ = fmt.Fprintln(w, "       nebula-agent service <install|start|stop|restart|uninstall> [--config PATH]")
	_, _ = fmt.Fprintln(w, "       nebula-agent version")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "First run on a fresh host: nebula-agent --token-file PATH --server URL")
	_, _ = fmt.Fprintln(w, "Every subsequent run    : nebula-agent")
}

// standbyTick is how often the daemon re-checks the filesystem for a
// freshly written enrollment while in standby (#88). Exposed as a var
// rather than const so tests can shorten it; production callers must
// not mutate it at runtime.
var standbyTick = 10 * time.Second

const (
	rekeyRetryInitialDelay = time.Second
	rekeyRetryMaxDelay     = time.Minute
)

// rekeyRetryDelay returns an exponentially increasing, bounded delay for
// consecutive re-enrollment failures. A new Poller performs its first poll
// immediately, so this delay is the only throttle between failed rekey
// attempts.
func rekeyRetryDelay(consecutiveFailures int) time.Duration {
	if consecutiveFailures <= 1 {
		return rekeyRetryInitialDelay
	}

	delay := rekeyRetryInitialDelay
	for attempt := 1; attempt < consecutiveFailures && delay < rekeyRetryMaxDelay; attempt++ {
		if delay > rekeyRetryMaxDelay/2 {
			return rekeyRetryMaxDelay
		}
		delay *= 2
	}
	return delay
}

// waitForRekeyRetry makes the retry delay interruptible by SIGTERM/SIGINT.
// It deliberately uses a timer instead of Sleep so stopping the agent never
// waits for a backoff window to elapse.
func waitForRekeyRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// runUnified is the daemon entrypoint. After #88 it never fails fast on a
// missing config or missing enrollment; instead it parks in standby and
// re-checks every standbyTick until the operator runs `nebula-agent enroll`
// (or systemd is told to stop the process).
//
// The legacy one-shot flow (`nebula-agent --server URL --token TOK`) still
// works: when both flags are set the agent enrolls and immediately starts
// the poll loop, just like before. That branch is used by Docker / non-
// systemd setups and by `nebula-agent enroll` itself for its confirmation
// poll.
func runUnified(ctx context.Context, args []string, stderr io.Writer) error {
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return runUnifiedWithLogger(ctx, args, stderr, logger)
}

func runUnifiedWithLogger(ctx context.Context, args []string, stderr io.Writer, logger *slog.Logger) error {
	fs := flag.NewFlagSet("nebula-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	serverURL := fs.String("server", "", "management server URL (one-shot enroll+poll)")
	token := fs.String("token", "", "bootstrap token (one-shot bootstrap+poll; prefer --token-file)")
	tokenFile := fs.String("token-file", "", "read bootstrap token from an owner-controlled file")
	dataDir := fs.String("data-dir", "", "override data directory (one-shot flow only)")
	nebulaConfigPath := fs.String("nebula-config-path", "", "existing Nebula config file path")
	pollInterval := fs.Duration("poll-interval", 0, "override poll interval (one-shot flow only)")
	updateConfig := fs.Bool("update-config", false, "overwrite on-disk config with CLI flags")
	force := fs.Bool("force", false, "destructively replace an existing installation with fresh enrollment")
	yes := fs.Bool("yes", false, "confirm import of the discovered existing Nebula installation")
	insecureHTTP := fs.Bool("insecure-http", false, "allow a plaintext http:// server URL on a non-loopback host (enrollment token and Nebula config transit in cleartext)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// One-shot enroll+poll path — explicit operator intent on the command
	// line. Preserves the pre-#88 behavior.
	if (*token != "" || *tokenFile != "") && *serverURL != "" {
		bootstrapToken, err := readBootstrapToken(*token, *tokenFile, stderr)
		if err != nil {
			return err
		}
		discoveryPath := *nebulaConfigPath
		preliminaryDataDir := *dataDir
		if preliminaryDataDir == "" {
			preliminaryDataDir = config.DefaultAgentConfig().DataDir
		}
		if discoveryPath == "" {
			discoveryPath = filepath.Join(preliminaryDataDir, "config.yml")
			if existing, loadErr := config.LoadAgentConfig(*configPath); loadErr == nil && existing.NebulaConfigPath != "" {
				discoveryPath = existing.NebulaConfigPath
			}
		}
		discovery, err := agent.DiscoverExisting(discoveryPath)
		if err != nil {
			return fmt.Errorf("discover existing Nebula installation: %w", err)
		}
		action, err := agent.DecideBootstrap(discovery.State, bootstrapToken, *force)
		if err != nil {
			return err
		}
		if action == agent.BootstrapImport {
			for _, line := range discovery.Manifest {
				logger.Info("discovered existing Nebula file", "path", line)
			}
			if !*yes {
				discovery.Wipe()
				return fmt.Errorf("existing Nebula installation found; inspect the manifest and rerun with --yes to import")
			}
			if err := config.ValidateAgentServerURL(*serverURL, *insecureHTTP); err != nil {
				discovery.Wipe()
				return err
			}
			signingPath := filepath.Join(filepath.Dir(*configPath), "host.signing.key")
			result, err := agent.ImportExisting(ctx, *serverURL, bootstrapToken, signingPath, discovery)
			if err != nil {
				return fmt.Errorf("existing mesh import failed: %w", err)
			}
			cfg := config.DefaultAgentConfig()
			cfg.ServerURL = *serverURL
			cfg.AllowInsecureHTTP = *insecureHTTP
			cfg.DataDir = preliminaryDataDir
			cfg.SigningKeyPath = signingPath
			if *pollInterval > 0 {
				cfg.PollInterval = *pollInterval
			}
			cfg.NebulaConfigPath = discovery.Snapshot.Profile.NebulaConfigPath
			cfg.NebulaCAPath = discovery.Snapshot.Profile.NebulaCAPath
			cfg.NebulaCertPath = discovery.Snapshot.Profile.NebulaCertPath
			cfg.NebulaKeyPath = discovery.Snapshot.Profile.NebulaKeyPath
			cfg.ImportSessionID = result.SessionID
			if err := config.SaveAgentConfig(*configPath, cfg); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			return startPoller(ctx, cfg, logger)
		}
		cfg, err := resolveConfig(*configPath, *serverURL, *dataDir, *pollInterval, *updateConfig, *insecureHTTP, stderr)
		if err != nil {
			return err
		}
		certPath := filepath.Join(cfg.DataDir, "host.crt")
		if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) || *force {
			logger.Info("enrolling host", "server", cfg.ServerURL, "data_dir", cfg.DataDir, "signing_key", cfg.SigningKeyPath)
			if err := agent.Enroll(ctx, cfg.ServerURL, bootstrapToken, cfg.DataDir, cfg.SigningKeyPath, cfg.NebulaConfigPath); err != nil {
				return fmt.Errorf("enrollment failed: %w", err)
			}
			logger.Info("enrollment successful")
		} else if err != nil {
			return fmt.Errorf("stat host certificate: %w", err)
		}
		return startPoller(ctx, cfg, logger)
	}

	// Daemon path — block in standby until the operator runs
	// `nebula-agent enroll`, then transition to the poll loop.
	cfg, err := awaitEnrollment(ctx, logger, *configPath)
	if err != nil {
		return err
	}
	return startPoller(ctx, cfg, logger)
}

// awaitEnrollment blocks until the agent has a usable config and the three
// on-disk artifacts the poller needs (agent.yml, host.crt, signing key).
// Returns ctx.Err() when the context is canceled. The standby hint is
// logged exactly once per process lifetime, even across multiple reasons,
// to keep journals readable.
func awaitEnrollment(ctx context.Context, logger *slog.Logger, configPath string) (*config.AgentConfig, error) {
	cfg, reason := checkEnrollment(configPath)
	if cfg != nil {
		return cfg, nil
	}
	// A config file that exists but fails to load is a misconfiguration the
	// operator must act on — most notably the https-required guard refusing
	// a pre-existing plaintext server_url after an upgrade — not the routine
	// "not enrolled yet" state. Surface it at Warn with the load error and
	// the remediation, so it doesn't read as a normal standby.
	if _, statErr := os.Stat(configPath); statErr == nil {
		if _, loadErr := config.LoadAgentConfig(configPath); loadErr != nil {
			logger.Warn("nebula-agent standby — config present but rejected; fix it or set allow_insecure_http to opt out", "error", loadErr, "config", configPath, "tick", standbyTick)
		}
	}
	logger.Info("nebula-agent standby — run `nebula-agent enroll --server URL --token TOK` to bind", "reason", reason, "config", configPath, "tick", standbyTick)
	ticker := time.NewTicker(standbyTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			cfg, reason = checkEnrollment(configPath)
			if cfg != nil {
				logger.Info("enrollment detected; leaving standby", "config", configPath)
				return cfg, nil
			}
			// Suppress per-tick log noise; the one-time hint above is
			// enough. reason is recomputed for the next iteration only.
			_ = reason
		}
	}
}

// checkEnrollment returns the loaded config when every required on-disk
// artifact is present, and a short human-readable reason string otherwise.
// All errors map to "missing" — the standby loop only cares whether the
// agent is ready to poll, not why a previous attempt failed.
func checkEnrollment(configPath string) (*config.AgentConfig, string) {
	if _, err := os.Stat(configPath); err != nil {
		return nil, "config missing: " + configPath
	}
	cfg, err := config.LoadAgentConfig(configPath)
	if err != nil {
		return nil, "config invalid: " + err.Error()
	}
	if _, err := os.Stat(cfg.ResolvedNebulaCertPath()); err != nil {
		return nil, "host certificate missing: " + cfg.ResolvedNebulaCertPath()
	}
	if _, err := os.Stat(cfg.SigningKeyPath); err != nil {
		return nil, "signing key missing: " + cfg.SigningKeyPath
	}
	return cfg, ""
}

// resolveConfig loads the on-disk config or creates one from CLI flags.
// CLI flags conflicting with an existing config are warned about unless
// --update-config is set, in which case they overwrite the file.
func resolveConfig(path, serverURL, dataDir string, pollInterval time.Duration, updateConfig, insecureHTTP bool, stderr io.Writer) (*config.AgentConfig, error) {
	if _, err := os.Stat(path); err == nil {
		cfg, err := config.LoadAgentConfig(path)
		if err != nil {
			return nil, fmt.Errorf("load config: %w", err)
		}
		applied := applyOverrides(cfg, serverURL, dataDir, pollInterval, updateConfig, stderr)
		if updateConfig && applied {
			if err := config.SaveAgentConfig(path, cfg); err != nil {
				return nil, fmt.Errorf("update config: %w", err)
			}
			_, _ = fmt.Fprintf(stderr, "config updated: %s\n", path)
		}
		return cfg, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("stat config: %w", err)
	}

	if serverURL == "" {
		return nil, fmt.Errorf("config %s not found and --server not set; pass --server URL on first run", path)
	}
	cfg := config.DefaultAgentConfig()
	cfg.ServerURL = serverURL
	cfg.AllowInsecureHTTP = insecureHTTP
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if pollInterval > 0 {
		cfg.PollInterval = pollInterval
	}
	// SaveAgentConfig validates the URL (https-required guard), so a
	// refused URL fails here — before the enrollment token is sent.
	if err := config.SaveAgentConfig(path, cfg); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	_, _ = fmt.Fprintf(stderr, "wrote config: %s\n", path)
	return cfg, nil
}

// applyOverrides compares CLI overrides with the on-disk config and either
// warns (default) or overwrites (when updateConfig is true). Returns true when
// any field actually changed.
func applyOverrides(cfg *config.AgentConfig, serverURL, dataDir string, pollInterval time.Duration, updateConfig bool, stderr io.Writer) bool {
	changed := false
	maybeApply := func(field, current, override string) string {
		if override == "" || override == current {
			return current
		}
		if updateConfig {
			_, _ = fmt.Fprintf(stderr, "overwriting %s: %q -> %q\n", field, current, override)
			changed = true
			return override
		}
		_, _ = fmt.Fprintf(stderr, "warning: --%s=%q ignored (config has %q); use --update-config to overwrite\n", field, override, current)
		return current
	}
	cfg.ServerURL = maybeApply("server", cfg.ServerURL, serverURL)
	cfg.DataDir = maybeApply("data-dir", cfg.DataDir, dataDir)
	if pollInterval > 0 && pollInterval != cfg.PollInterval {
		if updateConfig {
			_, _ = fmt.Fprintf(stderr, "overwriting poll-interval: %v -> %v\n", cfg.PollInterval, pollInterval)
			cfg.PollInterval = pollInterval
			changed = true
		} else {
			_, _ = fmt.Fprintf(stderr, "warning: --poll-interval=%v ignored (config has %v); use --update-config to overwrite\n", pollInterval, cfg.PollInterval)
		}
	}
	return changed
}

func startPoller(ctx context.Context, cfg *config.AgentConfig, logger *slog.Logger) error {
	logger.Info("nebula-agent starting", "server", cfg.ServerURL, "poll_interval", cfg.PollInterval)

	consecutiveRekeyFailures := 0
	for {
		fingerprint, err := agent.ReadCertFingerprintAt(cfg.ResolvedNebulaCertPath())
		if err != nil {
			return fmt.Errorf("read certificate fingerprint: %w", err)
		}
		poller, err := agent.NewPoller(agent.PollerConfig{
			ServerURL:        cfg.ServerURL,
			Fingerprint:      fingerprint,
			DataDir:          cfg.DataDir,
			SigningKeyPath:   cfg.SigningKeyPath,
			Interval:         cfg.PollInterval,
			PIDFile:          cfg.NebulaPIDFile,
			ReloadCommand:    cfg.NebulaReloadCommand,
			NebulaConfigPath: cfg.NebulaConfigPath,
			NebulaCAPath:     cfg.ResolvedNebulaCAPath(),
			NebulaCertPath:   cfg.ResolvedNebulaCertPath(),
			NebulaKeyPath:    cfg.ResolvedNebulaKeyPath(),
			ImportSessionID:  cfg.ImportSessionID,
		}, logger)
		if err != nil {
			return fmt.Errorf("create poller: %w", err)
		}

		runErr := poller.Run(ctx)
		if runErr == nil || errors.Is(runErr, context.Canceled) {
			return nil
		}
		if agent.IsRevoked(runErr) {
			// 403 revoked / 410 gone: operator stopped this agent. Exit
			// cleanly so systemd does not restart us into a denied loop.
			logger.Error("agent revoked; exiting cleanly", "error", runErr)
			return nil
		}
		if agent.IsRekey(runErr) {
			// Server-initiated rekey: re-enroll with the new token and
			// restart the poller against the freshly generated keypair.
			var re *agent.RekeyError
			_ = errors.As(runErr, &re)
			logger.Info("performing server-requested rekey")
			if err := agent.Reenroll(ctx, cfg.ServerURL, re.Token, agent.ReenrollOptions{
				DataDir: cfg.DataDir, SigningKeyPath: cfg.SigningKeyPath, PIDFile: cfg.NebulaPIDFile,
				ReloadCommand: cfg.NebulaReloadCommand,
				Profile: models.AgentProfile{
					NebulaConfigPath: cfg.NebulaConfigPath, NebulaCAPath: cfg.ResolvedNebulaCAPath(),
					NebulaCertPath: cfg.ResolvedNebulaCertPath(), NebulaKeyPath: cfg.ResolvedNebulaKeyPath(),
					ConfigAckV1: true,
				},
			}); err != nil {
				// Keep polling rather than exiting. A rekey can fail for
				// reasons the next attempt may not hit (an unwritable
				// directory an operator is about to fix, a server blip), and
				// the server re-offers it until the enrollment completes.
				// A new Poller polls immediately, so wait here rather than
				// relying on PollInterval or the service manager to throttle
				// persistent local failures.
				consecutiveRekeyFailures++
				delay := rekeyRetryDelay(consecutiveRekeyFailures)
				logger.Error("rekey enrollment failed; retrying after backoff", "error", err, "retry_in", delay)
				if waitErr := waitForRekeyRetry(ctx, delay); waitErr != nil {
					if errors.Is(waitErr, context.Canceled) {
						return nil
					}
					return waitErr
				}
			} else {
				consecutiveRekeyFailures = 0
			}
			continue
		}
		return runErr
	}
}

// runEnroll is the first-class `nebula-agent enroll` subcommand (#88). It
// performs the enrollment side-effects (generate keypairs, hit
// /api/v1/enroll, atomically persist agent.yml + the five enrollment files,
// run one confirmation poll) and exits. It is designed to be called by an
// operator from a shell — the long-running poll loop belongs to the
// systemd-managed daemon, which picks up the freshly written files on its
// next idle tick.
func runEnroll(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "agent config file path")
	serverURL := fs.String("server", "", "management server URL (required)")
	token := fs.String("token", "", "bootstrap token (never persisted; prefer --token-file)")
	tokenFile := fs.String("token-file", "", "read bootstrap token from an owner-controlled file")
	dataDir := fs.String("data-dir", "/etc/nebula", "Nebula data directory")
	nebulaConfigPath := fs.String("nebula-config-path", "", "path Nebula reads its rendered config from; defaults to <data-dir>/config.yml")
	signingKeyPath := fs.String("signing-key-path", "", "Ed25519 PoP signing key path; defaults to <config-dir>/host.signing.key")
	pollInterval := fs.Duration("poll-interval", 30*time.Second, "poll interval written to agent.yml")
	force := fs.Bool("force", false, "overwrite an existing enrollment")
	yes := fs.Bool("yes", false, "confirm import of the discovered existing Nebula installation")
	insecureHTTP := fs.Bool("insecure-http", false, "allow a plaintext http:// server URL on a non-loopback host (enrollment token and Nebula config transit in cleartext)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bootstrapToken, err := readBootstrapToken(*token, *tokenFile, stderr)
	if err != nil {
		return err
	}
	if *serverURL == "" || bootstrapToken == "" {
		return fmt.Errorf("--server and one of --token or --token-file are required")
	}
	// Validate before agent.Enroll so a refused URL never carries the
	// single-use enrollment token over cleartext.
	if err := config.ValidateAgentServerURL(*serverURL, *insecureHTTP); err != nil {
		return err
	}
	if *signingKeyPath == "" {
		*signingKeyPath = filepath.Join(filepath.Dir(*configPath), "host.signing.key")
	}
	resolvedConfigPath := *nebulaConfigPath
	if resolvedConfigPath == "" {
		resolvedConfigPath = filepath.Join(*dataDir, "config.yml")
	}
	discovery, err := agent.DiscoverExisting(resolvedConfigPath)
	if err != nil {
		return fmt.Errorf("discover existing Nebula installation: %w", err)
	}
	action, err := agent.DecideBootstrap(discovery.State, bootstrapToken, *force)
	if err != nil {
		if discovery.State != agent.DiscoveryNone {
			return fmt.Errorf("already enrolled or unsafe existing installation: %w", err)
		}
		return err
	}
	if action == agent.BootstrapImport {
		for _, line := range discovery.Manifest {
			_, _ = fmt.Fprintln(stdout, line)
		}
		if !*yes {
			discovery.Wipe()
			return fmt.Errorf("existing Nebula installation found; inspect the manifest and rerun with --yes to import")
		}
		result, err := agent.ImportExisting(ctx, *serverURL, bootstrapToken, *signingKeyPath, discovery)
		if err != nil {
			return fmt.Errorf("existing mesh import failed: %w", err)
		}
		cfg := config.DefaultAgentConfig()
		cfg.ServerURL = *serverURL
		cfg.AllowInsecureHTTP = *insecureHTTP
		cfg.DataDir = *dataDir
		cfg.SigningKeyPath = *signingKeyPath
		cfg.PollInterval = *pollInterval
		cfg.NebulaConfigPath = discovery.Snapshot.Profile.NebulaConfigPath
		cfg.NebulaCAPath = discovery.Snapshot.Profile.NebulaCAPath
		cfg.NebulaCertPath = discovery.Snapshot.Profile.NebulaCertPath
		cfg.NebulaKeyPath = discovery.Snapshot.Profile.NebulaKeyPath
		cfg.ImportSessionID = result.SessionID
		if err := config.SaveAgentConfig(*configPath, cfg); err != nil {
			return fmt.Errorf("write %s: %w", *configPath, err)
		}
		_, _ = fmt.Fprintf(stdout, "wrote %s\n", *configPath)
		confirmBootstrapPoll(ctx, cfg, stdout, stderr, "import")
		return nil
	}

	// Refuse to overwrite an existing enrollment unless --force.
	if !*force {
		for _, p := range []string{
			*configPath,
			filepath.Join(*dataDir, "host.crt"),
			*signingKeyPath,
		} {
			if _, err := os.Stat(p); err == nil {
				return fmt.Errorf("already enrolled (found %s); pass --force to overwrite", p)
			} else if !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("stat %s: %w", p, err)
			}
		}
	}

	// Resolve the rendered-config path once: an explicit --nebula-config-path
	// wins, otherwise it defaults to <data-dir>/config.yml. The same value is
	// passed to Enroll (initial write) and recorded in agent.yml so the daemon
	// rewrites the same file (#224) — no longer hardcoded to data-dir/config.yml.
	_, _ = fmt.Fprintf(stdout, "enrolling with %s...\n", *serverURL)
	if err := agent.Enroll(ctx, *serverURL, bootstrapToken, *dataDir, *signingKeyPath, resolvedConfigPath); err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	cfg := config.DefaultAgentConfig()
	cfg.ServerURL = *serverURL
	cfg.AllowInsecureHTTP = *insecureHTTP
	cfg.DataDir = *dataDir
	cfg.SigningKeyPath = *signingKeyPath
	cfg.PollInterval = *pollInterval
	cfg.NebulaConfigPath = resolvedConfigPath
	if err := config.SaveAgentConfig(*configPath, cfg); err != nil {
		return fmt.Errorf("write %s: %w", *configPath, err)
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", *configPath)

	// One confirmation poll so the operator sees "enrollment + first poll
	// succeeded" in the same command. Failures here are informational —
	// the on-disk state is good; the idle daemon will retry.
	fingerprint, err := agent.ReadCertFingerprintAt(cfg.ResolvedNebulaCertPath())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: cannot read fresh cert fingerprint: %v\n", err)
		_, _ = fmt.Fprintln(stdout, "enrollment successful (confirmation poll skipped)")
		return nil
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	poller, err := agent.NewPoller(agent.PollerConfig{
		ServerURL:        cfg.ServerURL,
		Fingerprint:      fingerprint,
		DataDir:          cfg.DataDir,
		SigningKeyPath:   cfg.SigningKeyPath,
		Interval:         cfg.PollInterval,
		NebulaConfigPath: cfg.NebulaConfigPath,
		NebulaCAPath:     cfg.ResolvedNebulaCAPath(),
		NebulaCertPath:   cfg.ResolvedNebulaCertPath(),
		NebulaKeyPath:    cfg.ResolvedNebulaKeyPath(),
		ImportSessionID:  cfg.ImportSessionID,
	}, logger)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: poller init failed: %v\n", err)
		_, _ = fmt.Fprintln(stdout, "enrollment successful (confirmation poll skipped)")
		return nil
	}
	if err := poller.PollOnce(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: first poll failed (enrollment files are valid; daemon will retry): %v\n", err)
		_, _ = fmt.Fprintln(stdout, "enrollment successful")
		return nil
	}
	_, _ = fmt.Fprintln(stdout, "enrollment successful (confirmation poll OK)")
	return nil
}

func readBootstrapToken(direct, path string, stderr io.Writer) (string, error) {
	if direct != "" && path != "" {
		return "", fmt.Errorf("use only one of --token or --token-file")
	}
	if path != "" {
		file, err := os.Open(path) // #nosec G304 -- operator-supplied bootstrap token file
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		defer file.Close()
		contents, err := io.ReadAll(io.LimitReader(file, 16<<10))
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		if len(contents) == 16<<10 {
			return "", fmt.Errorf("token file is too large")
		}
		return strings.TrimSpace(string(contents)), nil
	}
	if direct != "" {
		_, _ = fmt.Fprintln(stderr, "warning: --token may be retained in shell history; prefer --token-file")
	}
	return strings.TrimSpace(direct), nil
}

func confirmBootstrapPoll(ctx context.Context, cfg *config.AgentConfig, stdout, stderr io.Writer, workflow string) {
	fingerprint, err := agent.ReadCertFingerprintAt(cfg.ResolvedNebulaCertPath())
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: cannot read host cert fingerprint: %v\n", err)
		_, _ = fmt.Fprintf(stdout, "%s successful (confirmation poll skipped)\n", workflow)
		return
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	poller, err := agent.NewPoller(agent.PollerConfig{
		ServerURL: cfg.ServerURL, Fingerprint: fingerprint, DataDir: cfg.DataDir,
		SigningKeyPath: cfg.SigningKeyPath, Interval: cfg.PollInterval,
		NebulaConfigPath: cfg.NebulaConfigPath,
		NebulaCAPath:     cfg.ResolvedNebulaCAPath(),
		NebulaCertPath:   cfg.ResolvedNebulaCertPath(),
		NebulaKeyPath:    cfg.ResolvedNebulaKeyPath(),
		ImportSessionID:  cfg.ImportSessionID,
	}, logger)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: poller init failed: %v\n", err)
		_, _ = fmt.Fprintf(stdout, "%s successful (confirmation poll skipped)\n", workflow)
		return
	}
	if err := poller.PollOnce(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: first poll failed: %v\n", err)
		_, _ = fmt.Fprintf(stdout, "%s successful\n", workflow)
		return
	}
	_, _ = fmt.Fprintf(stdout, "%s successful (confirmation poll OK)\n", workflow)
}

func runLegacyRun(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.LoadAgentConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return startPoller(ctx, cfg, logger)
}
