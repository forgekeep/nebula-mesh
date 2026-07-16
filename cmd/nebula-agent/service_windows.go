//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/kardianos/service"
)

const (
	agentServiceStopTimeout    = 5 * time.Second
	agentServiceControlTimeout = 30 * time.Second
)

func runService(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	command, err := parseAgentServiceCommand(args, stderr)
	if err != nil {
		return err
	}

	configPath := command.configPath
	if configPath == "" {
		configPath = defaultConfigPath
	}
	serviceConfig, err := newAgentServiceConfig(configPath)
	if err != nil {
		return err
	}

	runner := func(runCtx context.Context, logger *slog.Logger) error {
		return runUnifiedWithLogger(runCtx, []string{"--config", serviceConfig.Arguments[3]}, io.Discard, logger)
	}
	program := newAgentServiceProgram(runner, service.ConsoleLogger, os.Exit, agentServiceStopTimeout)
	svc, err := newAgentSystemService(program, serviceConfig)
	if err != nil {
		return fmt.Errorf("create Windows service: %w", err)
	}
	logger, err := svc.Logger(nil)
	if err != nil {
		return fmt.Errorf("open service logger: %w", err)
	}
	program.logger = logger

	_ = stdout
	switch command.action {
	case "run":
		if err := svc.Run(); err != nil {
			return fmt.Errorf("run Windows service: %w", err)
		}
		return nil
	case "install":
		if err := svc.Install(); err != nil {
			return fmt.Errorf("install Windows service: %w", err)
		}
		return nil
	case "uninstall":
		if err := svc.Uninstall(); err != nil {
			return fmt.Errorf("uninstall Windows service: %w", err)
		}
		return nil
	case "start":
		if err := svc.Start(); err != nil {
			return fmt.Errorf("start Windows service: %w", err)
		}
		return nil
	case "stop":
		return runBoundedServiceControl(ctx, agentServiceControlTimeout, "stop", svc.Stop)
	case "restart":
		return runBoundedServiceControl(ctx, agentServiceControlTimeout, "restart", svc.Restart)
	default:
		return fmt.Errorf("unsupported service action %q", command.action)
	}
}
