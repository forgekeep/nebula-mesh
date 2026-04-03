package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/juev/nebula-mesh/internal/agent"
	"github.com/juev/nebula-mesh/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: nebula-agent <command> [flags]")
		fmt.Fprintln(os.Stderr, "commands: enroll, run")
		return fmt.Errorf("no command specified")
	}

	switch os.Args[1] {
	case "enroll":
		return runEnroll(os.Args[2:])
	case "run":
		return runAgent(os.Args[2:])
	default:
		return fmt.Errorf("unknown command: %s", os.Args[1])
	}
}

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "enrollment token")
	serverURL := fs.String("server", "", "management server URL")
	dataDir := fs.String("data-dir", "/etc/nebula", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *token == "" || *serverURL == "" {
		return fmt.Errorf("--token and --server are required")
	}

	fmt.Printf("enrolling with server %s...\n", *serverURL)
	if err := agent.Enroll(*serverURL, *token, *dataDir); err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	fmt.Println("enrollment successful")
	return nil
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "/etc/nebula-agent/agent.yml", "config file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadAgentConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Read current fingerprint from certificate
	fingerprint, err := agent.ReadCertFingerprint(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("read certificate fingerprint: %w (did you run 'enroll' first?)", err)
	}

	poller := agent.NewPoller(cfg.ServerURL, fingerprint, cfg.DataDir, cfg.PollInterval, logger)

	// Graceful shutdown
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
	return poller.Run(ctx)
}
