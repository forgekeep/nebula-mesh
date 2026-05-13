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

	"github.com/juev/nebula-mesh/internal/agent"
	"github.com/juev/nebula-mesh/internal/config"
	"github.com/juev/nebula-mesh/internal/version"
)

// Populated at build time via -ldflags (see .goreleaser.yml).
var (
	versionStr = "dev"
	commit     = "none"
	date       = "unknown"
)

const defaultConfigPath = "/etc/nebula-agent/agent.yml"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	// Dispatch deprecated subcommands first so the unified flag set does not
	// need to understand "enroll" / "run" as positional arguments.
	if len(args) > 0 {
		switch args[0] {
		case "enroll":
			_, _ = fmt.Fprintln(stderr, "warning: `nebula-agent enroll` is deprecated; pass --token and --server to `nebula-agent` instead")
			return runLegacyEnroll(args[1:], stderr)
		case "run":
			_, _ = fmt.Fprintln(stderr, "warning: `nebula-agent run` is deprecated; invoke `nebula-agent` without a subcommand")
			return runLegacyRun(args[1:], stderr)
		case "version", "--version", "-v":
			version.Print(stdout, "nebula-agent", versionStr, commit, date)
			return nil
		case "-h", "--help", "help":
			printUsage(stderr)
			return nil
		}
	}

	return runUnified(args, stderr)
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage: nebula-agent [--config PATH] [--token TOK --server URL] [--data-dir DIR] [--update-config]")
	_, _ = fmt.Fprintln(w, "       nebula-agent version")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "First run on a fresh host: nebula-agent --token TOK --server URL")
	_, _ = fmt.Fprintln(w, "Every subsequent run    : nebula-agent")
}

// runUnified is the single-command entrypoint described in issue #67.
//
// Startup algorithm:
//  1. Resolve config path (--config PATH or defaultConfigPath).
//  2. If config exists → load it; warn when CLI flags conflict; --update-config
//     overwrites fields with CLI values before starting.
//  3. If config missing → build AgentConfig from defaults + CLI flags, write
//     it atomically. --server is required for first run.
//  4. After config is in place:
//     a. cert exists → start poller.
//     b. cert missing and --token set → enroll, then start poller.
//     c. cert missing and no --token → fatal with hint.
//
// The enrollment token is never written to disk.
func runUnified(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("nebula-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "config file path")
	serverURL := fs.String("server", "", "management server URL (first run only)")
	token := fs.String("token", "", "enrollment token (first run only, never written to disk)")
	dataDir := fs.String("data-dir", "", "override data directory (first run only)")
	pollInterval := fs.Duration("poll-interval", 0, "override poll interval (first run only)")
	updateConfig := fs.Bool("update-config", false, "overwrite on-disk config with CLI flags")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := resolveConfig(*configPath, *serverURL, *dataDir, *pollInterval, *updateConfig, stderr)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	certPath := filepath.Join(cfg.DataDir, "host.crt")
	switch _, err := os.Stat(certPath); {
	case err == nil:
		// Already enrolled — fall through to poller.
	case errors.Is(err, os.ErrNotExist):
		if *token == "" {
			return fmt.Errorf("no host certificate at %s and no --token to enroll with; pass --token TOK to enroll", certPath)
		}
		logger.Info("enrolling host", "server", cfg.ServerURL, "data_dir", cfg.DataDir)
		if err := agent.Enroll(cfg.ServerURL, *token, cfg.DataDir); err != nil {
			return fmt.Errorf("enrollment failed: %w", err)
		}
		logger.Info("enrollment successful")
	default:
		return fmt.Errorf("stat host certificate: %w", err)
	}

	return startPoller(cfg, logger)
}

// resolveConfig loads the on-disk config or creates one from CLI flags.
// CLI flags conflicting with an existing config are warned about unless
// --update-config is set, in which case they overwrite the file.
func resolveConfig(path, serverURL, dataDir string, pollInterval time.Duration, updateConfig bool, stderr io.Writer) (*config.AgentConfig, error) {
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
	if dataDir != "" {
		cfg.DataDir = dataDir
	}
	if pollInterval > 0 {
		cfg.PollInterval = pollInterval
	}
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

func startPoller(cfg *config.AgentConfig, logger *slog.Logger) error {
	fingerprint, err := agent.ReadCertFingerprint(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("read certificate fingerprint: %w", err)
	}

	poller, err := agent.NewPoller(agent.PollerConfig{
		ServerURL:   cfg.ServerURL,
		Fingerprint: fingerprint,
		DataDir:     cfg.DataDir,
		Interval:    cfg.PollInterval,
		PIDFile:     cfg.NebulaPIDFile,
	}, logger)
	if err != nil {
		return fmt.Errorf("create poller: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	logger.Info("nebula-agent starting", "server", cfg.ServerURL, "poll_interval", cfg.PollInterval)
	if err := poller.Run(ctx); err != nil {
		// A 403 revoked / 410 gone signal means the operator deliberately
		// stopped this agent. Exit cleanly so systemd does not restart us
		// into the same denied state on a loop.
		if agent.IsRevoked(err) {
			logger.Error("agent revoked; exiting cleanly", "error", err)
			return nil
		}
		return err
	}
	return nil
}

// runLegacyEnroll preserves the old `nebula-agent enroll` invocation for one
// release. It does not persist any config — operators get the unified flow
// the next time they invoke the agent.
func runLegacyEnroll(args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "enrollment token")
	serverURL := fs.String("server", "", "management server URL")
	dataDir := fs.String("data-dir", "/etc/nebula", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *serverURL == "" {
		return fmt.Errorf("--token and --server are required")
	}
	_, _ = fmt.Fprintf(stderr, "enrolling with server %s...\n", *serverURL)
	if err := agent.Enroll(*serverURL, *token, *dataDir); err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}
	_, _ = fmt.Fprintln(stderr, "enrollment successful")
	return nil
}

func runLegacyRun(args []string, stderr io.Writer) error {
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
	return startPoller(cfg, logger)
}
