package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/service"
)

const (
	agentServiceName        = "NebulaMeshAgent"
	agentServiceDisplayName = "Nebula Mesh Agent"
	agentServiceDescription = "Polling agent for the Nebula Mesh management server"
)

type serviceRunner func(context.Context, *slog.Logger) error

type agentServiceCommand struct {
	action     string
	configPath string
}

var newAgentSystemService = service.New

type agentServiceProgram struct {
	mu          sync.Mutex
	runner      serviceRunner
	logger      service.Logger
	exit        func(int)
	stopTimeout time.Duration
	cancel      context.CancelFunc
	done        chan struct{}
	stopping    bool
}

func newAgentServiceConfig(configPath string) (*service.Config, error) {
	if configPath == "" {
		return nil, fmt.Errorf("service config path is required")
	}
	absolutePath, err := filepath.Abs(configPath)
	if err != nil {
		return nil, fmt.Errorf("resolve service config path: %w", err)
	}
	return &service.Config{
		Name:        agentServiceName,
		DisplayName: agentServiceDisplayName,
		Description: agentServiceDescription,
		Arguments:   []string{"service", "run", "--config", absolutePath},
		Option: service.KeyValue{
			"StartType":              "automatic",
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "5s",
		},
	}, nil
}

func parseAgentServiceCommand(args []string, stderr io.Writer) (agentServiceCommand, error) {
	if len(args) == 0 {
		return agentServiceCommand{}, fmt.Errorf("service action is required")
	}

	action := args[0]
	switch action {
	case "install", "start", "stop", "restart", "uninstall", "run":
	default:
		return agentServiceCommand{}, fmt.Errorf("unknown service action %q", action)
	}

	fs := flag.NewFlagSet("service "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "absolute path to the agent config file")
	if err := fs.Parse(args[1:]); err != nil {
		return agentServiceCommand{}, err
	}
	if fs.NArg() != 0 {
		return agentServiceCommand{}, fmt.Errorf("unexpected service arguments: %s", strings.Join(fs.Args(), " "))
	}
	if (action == "install" || action == "run") && *configPath == "" {
		return agentServiceCommand{}, fmt.Errorf("--config is required for service %s", action)
	}
	if action != "install" && action != "run" && *configPath != "" {
		return agentServiceCommand{}, fmt.Errorf("--config is only valid with service install or service run")
	}

	return agentServiceCommand{action: action, configPath: *configPath}, nil
}

func newAgentServiceProgram(runner serviceRunner, logger service.Logger, exit func(int), stopTimeout time.Duration) *agentServiceProgram {
	return &agentServiceProgram{
		runner:      runner,
		logger:      logger,
		exit:        exit,
		stopTimeout: stopTimeout,
	}
}

func (p *agentServiceProgram) Start(svc service.Service) error {
	p.mu.Lock()
	if p.cancel != nil {
		p.mu.Unlock()
		return fmt.Errorf("agent service is already started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	p.cancel = cancel
	p.done = done
	p.stopping = false
	p.mu.Unlock()

	go func() {
		err := p.runner(ctx, newServiceSlogLogger(p.logger))

		p.mu.Lock()
		stopping := p.stopping || ctx.Err() != nil
		close(done)
		p.mu.Unlock()

		if stopping {
			return
		}
		if err != nil {
			_ = p.logger.Errorf("Nebula Mesh agent stopped with an error: %v", err)
			p.exit(1)
			return
		}
		if svc == nil {
			_ = p.logger.Error("Nebula Mesh agent stopped cleanly, but no service control is available")
			p.exit(1)
			return
		}
		if err := svc.Stop(); err != nil {
			_ = p.logger.Errorf("stop Windows service after clean agent completion: %v", err)
			p.exit(1)
		}
	}()

	return nil
}

func (p *agentServiceProgram) Stop(service.Service) error {
	p.mu.Lock()
	if p.cancel == nil {
		p.mu.Unlock()
		return nil
	}
	p.stopping = true
	p.cancel()
	done := p.done
	stopTimeout := p.stopTimeout
	p.mu.Unlock()

	timer := time.NewTimer(stopTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return fmt.Errorf("agent service stop timed out after %s", stopTimeout)
	}
}

func runBoundedServiceControl(ctx context.Context, timeout time.Duration, action string, control func() error) error {
	result := make(chan error, 1)
	go func() {
		result <- control()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		if err != nil {
			return fmt.Errorf("service %s: %w", action, err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("service %s canceled: %w", action, ctx.Err())
	case <-timer.C:
		return fmt.Errorf("service %s timed out after %s", action, timeout)
	}
}

type serviceLogWriter struct {
	mu     sync.Mutex
	logger service.Logger
	level  slog.Level
}

func (w *serviceLogWriter) Write(p []byte) (int, error) {
	line := strings.TrimRight(string(p), "\r\n")
	var err error
	switch {
	case w.level >= slog.LevelError:
		err = w.logger.Error(line)
	case w.level >= slog.LevelWarn:
		err = w.logger.Warning(line)
	default:
		err = w.logger.Info(line)
	}
	return len(p), err
}

type serviceLogHandler struct {
	inner  slog.Handler
	writer *serviceLogWriter
}

func newServiceSlogLogger(logger service.Logger) *slog.Logger {
	writer := &serviceLogWriter{logger: logger}
	inner := slog.NewTextHandler(writer, nil)
	return slog.New(&serviceLogHandler{inner: inner, writer: writer})
}

func (h *serviceLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *serviceLogHandler) Handle(ctx context.Context, record slog.Record) error {
	h.writer.mu.Lock()
	defer h.writer.mu.Unlock()
	h.writer.level = record.Level
	return h.inner.Handle(ctx, record)
}

func (h *serviceLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &serviceLogHandler{inner: h.inner.WithAttrs(attrs), writer: h.writer}
}

func (h *serviceLogHandler) WithGroup(name string) slog.Handler {
	return &serviceLogHandler{inner: h.inner.WithGroup(name), writer: h.writer}
}
