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
	"syscall"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/agent"
	"github.com/forgekeep/nebula-mesh/internal/config"
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
	_, _ = fmt.Fprintln(w, "Usage: nebula-agent [--config PATH] [--token TOK --server URL] [--data-dir DIR] [--update-config]")
	_, _ = fmt.Fprintln(w, "       nebula-agent version")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "First run on a fresh host: nebula-agent --token TOK --server URL")
	_, _ = fmt.Fprintln(w, "Every subsequent run    : nebula-agent")
}

// standbyTick is how often the daemon re-checks the filesystem for a
// freshly written enrollment while in standby (#88). Exposed as a var
// rather than const so tests can shorten it; production callers must
// not mutate it at runtime.
var standbyTick = 10 * time.Second

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
	fs := flag.NewFlagSet("nebula-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	serverURL := fs.String("server", "", "management server URL (one-shot enroll+poll)")
	token := fs.String("token", "", "enrollment token (one-shot enroll+poll; never persisted)")
	dataDir := fs.String("data-dir", "", "override data directory (one-shot flow only)")
	pollInterval := fs.Duration("poll-interval", 0, "override poll interval (one-shot flow only)")
	updateConfig := fs.Bool("update-config", false, "overwrite on-disk config with CLI flags")
	insecureHTTP := fs.Bool("insecure-http", false, "allow a plaintext http:// server URL on a non-loopback host (enrollment token and Nebula config transit in cleartext)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// One-shot enroll+poll path — explicit operator intent on the command
	// line. Preserves the pre-#88 behavior.
	if *token != "" && *serverURL != "" {
		cfg, err := resolveConfig(*configPath, *serverURL, *dataDir, *pollInterval, *updateConfig, *insecureHTTP, stderr)
		if err != nil {
			return err
		}
		certPath := filepath.Join(cfg.DataDir, "host.crt")
		if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
			logger.Info("enrolling host", "server", cfg.ServerURL, "data_dir", cfg.DataDir, "signing_key", cfg.SigningKeyPath)
			if err := agent.Enroll(ctx, cfg.ServerURL, *token, cfg.DataDir, cfg.SigningKeyPath); err != nil {
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
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "host.crt")); err != nil {
		return nil, "host.crt missing in " + cfg.DataDir
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

	for {
		fingerprint, err := agent.ReadCertFingerprint(cfg.DataDir)
		if err != nil {
			return fmt.Errorf("read certificate fingerprint: %w", err)
		}
		poller, err := agent.NewPoller(agent.PollerConfig{
			ServerURL:      cfg.ServerURL,
			Fingerprint:    fingerprint,
			DataDir:        cfg.DataDir,
			SigningKeyPath: cfg.SigningKeyPath,
			Interval:       cfg.PollInterval,
			PIDFile:        cfg.NebulaPIDFile,
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
			if err := agent.Reenroll(ctx, cfg.ServerURL, re.Token, cfg.DataDir, cfg.SigningKeyPath); err != nil {
				return fmt.Errorf("rekey enrollment: %w", err)
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
	token := fs.String("token", "", "enrollment token (required; never persisted)")
	dataDir := fs.String("data-dir", "/etc/nebula", "Nebula data directory")
	signingKeyPath := fs.String("signing-key-path", "", "Ed25519 PoP signing key path; defaults to <config-dir>/host.signing.key")
	pollInterval := fs.Duration("poll-interval", 30*time.Second, "poll interval written to agent.yml")
	force := fs.Bool("force", false, "overwrite an existing enrollment")
	insecureHTTP := fs.Bool("insecure-http", false, "allow a plaintext http:// server URL on a non-loopback host (enrollment token and Nebula config transit in cleartext)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *serverURL == "" || *token == "" {
		return fmt.Errorf("--server and --token are required")
	}
	// Validate before agent.Enroll so a refused URL never carries the
	// single-use enrollment token over cleartext.
	if err := config.ValidateAgentServerURL(*serverURL, *insecureHTTP); err != nil {
		return err
	}
	if *signingKeyPath == "" {
		*signingKeyPath = filepath.Join(filepath.Dir(*configPath), "host.signing.key")
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

	_, _ = fmt.Fprintf(stdout, "enrolling with %s...\n", *serverURL)
	if err := agent.Enroll(ctx, *serverURL, *token, *dataDir, *signingKeyPath); err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	cfg := config.DefaultAgentConfig()
	cfg.ServerURL = *serverURL
	cfg.AllowInsecureHTTP = *insecureHTTP
	cfg.DataDir = *dataDir
	cfg.SigningKeyPath = *signingKeyPath
	cfg.PollInterval = *pollInterval
	cfg.NebulaConfigPath = filepath.Join(*dataDir, "config.yml")
	if err := config.SaveAgentConfig(*configPath, cfg); err != nil {
		return fmt.Errorf("write %s: %w", *configPath, err)
	}
	_, _ = fmt.Fprintf(stdout, "wrote %s\n", *configPath)

	// One confirmation poll so the operator sees "enrollment + first poll
	// succeeded" in the same command. Failures here are informational —
	// the on-disk state is good; the idle daemon will retry.
	fingerprint, err := agent.ReadCertFingerprint(*dataDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "warning: cannot read fresh cert fingerprint: %v\n", err)
		_, _ = fmt.Fprintln(stdout, "enrollment successful (confirmation poll skipped)")
		return nil
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	poller, err := agent.NewPoller(agent.PollerConfig{
		ServerURL:      cfg.ServerURL,
		Fingerprint:    fingerprint,
		DataDir:        cfg.DataDir,
		SigningKeyPath: cfg.SigningKeyPath,
		Interval:       cfg.PollInterval,
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
