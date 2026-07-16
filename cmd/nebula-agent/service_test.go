package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kardianos/service"
)

func TestParseAgentServiceCommand(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantAction string
		wantConfig string
		wantErr    string
	}{
		{name: "install", args: []string{"install", "--config", "agent.yml"}, wantAction: "install", wantConfig: "agent.yml"},
		{name: "internal run", args: []string{"run", "--config", "agent.yml"}, wantAction: "run", wantConfig: "agent.yml"},
		{name: "start", args: []string{"start"}, wantAction: "start"},
		{name: "stop", args: []string{"stop"}, wantAction: "stop"},
		{name: "restart", args: []string{"restart"}, wantAction: "restart"},
		{name: "uninstall", args: []string{"uninstall"}, wantAction: "uninstall"},
		{name: "missing action", wantErr: "service action is required"},
		{name: "unknown action", args: []string{"status"}, wantErr: "unknown service action"},
		{name: "install requires config", args: []string{"install"}, wantErr: "--config is required"},
		{name: "run requires config", args: []string{"run"}, wantErr: "--config is required"},
		{name: "config rejected for control", args: []string{"start", "--config", "agent.yml"}, wantErr: "--config is only valid"},
		{name: "positional argument rejected", args: []string{"start", "extra"}, wantErr: "unexpected service arguments"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := parseAgentServiceCommand(tt.args, &strings.Builder{})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseAgentServiceCommand() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAgentServiceCommand() error = %v", err)
			}
			if cmd.action != tt.wantAction || cmd.configPath != tt.wantConfig {
				t.Errorf("command = {%q %q}, want {%q %q}", cmd.action, cmd.configPath, tt.wantAction, tt.wantConfig)
			}
		})
	}
}

func TestServiceSubcommandIsExplicitlyUnsupportedOutsideWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows contract")
	}
	err := run(t.Context(), []string{"service", "start"}, &strings.Builder{}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "only supported on Windows") {
		t.Fatalf("run(service start) error = %v, want Windows-only error", err)
	}
}

func TestWindowsServiceDispatchUsesExpectedOperationAndLogger(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows service wiring")
	}

	actions := []string{"install", "start", "stop", "restart", "uninstall", "run"}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			fake := &fakeManagedService{logger: &fakeServiceLogger{}}
			originalFactory := newAgentSystemService
			newAgentSystemService = func(service.Interface, *service.Config) (service.Service, error) {
				return fake, nil
			}
			t.Cleanup(func() { newAgentSystemService = originalFactory })

			args := []string{action}
			if action == "install" || action == "run" {
				args = append(args, "--config", t.TempDir()+"/agent.yml")
			}
			if err := runService(t.Context(), args, &strings.Builder{}, &strings.Builder{}); err != nil {
				t.Fatalf("runService(%s) error = %v", action, err)
			}
			if fake.action != action {
				t.Errorf("service action = %q, want %q", fake.action, action)
			}
			if fake.loggerCalls != 1 || fake.systemLoggerCalls != 0 {
				t.Errorf("Logger/SystemLogger calls = %d/%d, want 1/0", fake.loggerCalls, fake.systemLoggerCalls)
			}
		})
	}
}

func TestAgentUsageListsWindowsServiceActions(t *testing.T) {
	var output strings.Builder
	printUsage(&output)
	got := output.String()
	if !strings.Contains(got, "service <install|start|stop|restart|uninstall>") {
		t.Fatalf("usage = %q, want service actions", got)
	}
}

func TestServiceConfigUsesAbsoluteDaemonArgumentsAndRecoveryPolicy(t *testing.T) {
	configPath := t.TempDir() + "/agent.yml"

	cfg, err := newAgentServiceConfig(configPath)
	if err != nil {
		t.Fatalf("newAgentServiceConfig() error = %v", err)
	}

	if cfg.Name != agentServiceName {
		t.Errorf("Name = %q, want %q", cfg.Name, agentServiceName)
	}
	if cfg.DisplayName != "Nebula Mesh Agent" {
		t.Errorf("DisplayName = %q, want %q", cfg.DisplayName, "Nebula Mesh Agent")
	}
	absolutePath, err := filepath.Abs(configPath)
	if err != nil {
		t.Fatalf("filepath.Abs() error = %v", err)
	}
	wantArgs := []string{"service", "run", "--config", absolutePath}
	if fmt.Sprint(cfg.Arguments) != fmt.Sprint(wantArgs) {
		t.Errorf("Arguments = %q, want %q", cfg.Arguments, wantArgs)
	}
	if got := cfg.Option["StartType"]; got != "automatic" {
		t.Errorf("StartType = %v, want automatic", got)
	}
	if got := cfg.Option["OnFailure"]; got != "restart" {
		t.Errorf("OnFailure = %v, want restart", got)
	}
	if got := cfg.Option["OnFailureDelayDuration"]; got != "5s" {
		t.Errorf("OnFailureDelayDuration = %v, want 5s", got)
	}
}

func TestServiceProgramStopCancelsRunnerReturningNilWithoutExit(t *testing.T) {
	started := make(chan struct{})
	exits := make(chan int, 1)
	runner := func(ctx context.Context, _ *slog.Logger) error {
		close(started)
		<-ctx.Done()
		return nil
	}
	p := newAgentServiceProgram(runner, &fakeServiceLogger{}, func(code int) {
		exits <- code
	}, time.Second)

	if err := p.Start(nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runner did not start")
	}

	if err := p.Stop(nil); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case code := <-exits:
		t.Fatalf("stop-driven runner called exit(%d)", code)
	case <-time.After(25 * time.Millisecond):
	}

	if err := p.Stop(nil); err != nil {
		t.Fatalf("second Stop() error = %v", err)
	}
}

func TestServiceProgramStopCancelsRunnerReturningContextErrorWithoutExit(t *testing.T) {
	exits := make(chan int, 1)
	runner := func(ctx context.Context, _ *slog.Logger) error {
		<-ctx.Done()
		return ctx.Err()
	}
	p := newAgentServiceProgram(runner, &fakeServiceLogger{}, func(code int) {
		exits <- code
	}, time.Second)

	if err := p.Start(nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := p.Stop(nil); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	select {
	case code := <-exits:
		t.Fatalf("stop-driven runner called exit(%d)", code)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestServiceProgramRequestsSCMStopOnCleanIndependentCompletion(t *testing.T) {
	stopped := make(chan struct{})
	exits := make(chan int, 1)
	p := newAgentServiceProgram(func(context.Context, *slog.Logger) error {
		return nil
	}, &fakeServiceLogger{}, func(code int) {
		exits <- code
	}, time.Second)

	if err := p.Start(&fakeManagedService{stopped: stopped}); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("clean runner completion did not request an SCM stop")
	}
	select {
	case code := <-exits:
		t.Fatalf("clean runner completion called exit(%d)", code)
	case <-time.After(25 * time.Millisecond):
	}
}

func TestServiceProgramMapsFatalIndependentCompletionToProcessExit(t *testing.T) {
	logger := &fakeServiceLogger{}
	exits := make(chan int, 1)
	p := newAgentServiceProgram(func(context.Context, *slog.Logger) error {
		return errors.New("poll failed")
	}, logger, func(code int) {
		exits <- code
	}, time.Second)

	if err := p.Start(nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	select {
	case code := <-exits:
		if code != 1 {
			t.Errorf("exit code = %d, want 1", code)
		}
	case <-time.After(time.Second):
		t.Fatal("fatal runner completion did not request process exit")
	}
	if !strings.Contains(logger.joinedErrors(), "poll failed") {
		t.Errorf("error log = %q, want poll failure", logger.joinedErrors())
	}
}

func TestServiceProgramStopIsBounded(t *testing.T) {
	release := make(chan struct{})
	p := newAgentServiceProgram(func(context.Context, *slog.Logger) error {
		<-release
		return nil
	}, &fakeServiceLogger{}, func(int) {}, 20*time.Millisecond)

	if err := p.Start(nil); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	err := p.Stop(nil)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("Stop() error = %v, want timeout", err)
	}
	close(release)
}

func TestBoundedServiceControlTimesOutAndReturnsUnderlyingError(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		err := runBoundedServiceControl(t.Context(), 20*time.Millisecond, "stop", func() error {
			<-release
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "stop timed out") {
			t.Fatalf("runBoundedServiceControl() error = %v, want stop timeout", err)
		}
		close(release)
	})

	t.Run("underlying error", func(t *testing.T) {
		wantErr := errors.New("SCM refused stop")
		err := runBoundedServiceControl(t.Context(), time.Second, "stop", func() error {
			return wantErr
		})
		if !errors.Is(err, wantErr) {
			t.Fatalf("runBoundedServiceControl() error = %v, want wrapped %v", err, wantErr)
		}
	})
}

func TestServiceLogHandlerPreservesSeverityAttrsAndGroups(t *testing.T) {
	logger := &fakeServiceLogger{}
	s := newServiceSlogLogger(logger)

	s.Info("ready", "service", agentServiceName)
	s.Warn("retry", "delay", "5s")
	s.With("host", "alpha").WithGroup("poll").Error("failed", "status", 503)

	if got := logger.joinedInfos(); !strings.Contains(got, "ready") || !strings.Contains(got, "service=NebulaMeshAgent") {
		t.Errorf("info log = %q, want message and attrs", got)
	}
	if got := logger.joinedWarnings(); !strings.Contains(got, "retry") || !strings.Contains(got, "delay=5s") {
		t.Errorf("warning log = %q, want message and attrs", got)
	}
	if got := logger.joinedErrors(); !strings.Contains(got, "failed") || !strings.Contains(got, "host=alpha") || !strings.Contains(got, "poll.status=503") {
		t.Errorf("error log = %q, want message, attrs and group", got)
	}
}

func TestServiceLogHandlerIsRaceSafe(t *testing.T) {
	logger := &fakeServiceLogger{}
	s := newServiceSlogLogger(logger)

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(3)
		go func(n int) {
			defer wg.Done()
			s.Info("info", "n", n)
		}(i)
		go func(n int) {
			defer wg.Done()
			s.Warn("warn", "n", n)
		}(i)
		go func(n int) {
			defer wg.Done()
			s.Error("error", "n", n)
		}(i)
	}
	wg.Wait()

	if logger.infoCount() != 25 || logger.warningCount() != 25 || logger.errorCount() != 25 {
		t.Fatalf("counts info/warn/error = %d/%d/%d, want 25/25/25", logger.infoCount(), logger.warningCount(), logger.errorCount())
	}
}

type fakeServiceLogger struct {
	mu       sync.Mutex
	infos    []string
	warnings []string
	errors   []string
}

type fakeManagedService struct {
	action            string
	logger            service.Logger
	loggerCalls       int
	systemLoggerCalls int
	stopped           chan struct{}
}

func (s *fakeManagedService) Run() error {
	s.action = "run"
	return nil
}

func (s *fakeManagedService) Start() error {
	s.action = "start"
	return nil
}

func (s *fakeManagedService) Stop() error {
	s.action = "stop"
	if s.stopped != nil {
		close(s.stopped)
	}
	return nil
}

func (s *fakeManagedService) Restart() error {
	s.action = "restart"
	return nil
}

func (s *fakeManagedService) Install() error {
	s.action = "install"
	return nil
}

func (s *fakeManagedService) Uninstall() error {
	s.action = "uninstall"
	return nil
}

func (s *fakeManagedService) Logger(chan<- error) (service.Logger, error) {
	s.loggerCalls++
	return s.logger, nil
}

func (s *fakeManagedService) SystemLogger(chan<- error) (service.Logger, error) {
	s.systemLoggerCalls++
	return s.logger, nil
}

func (s *fakeManagedService) String() string { return agentServiceDisplayName }

func (s *fakeManagedService) Platform() string { return "fake" }

func (s *fakeManagedService) Status() (service.Status, error) { return service.StatusStopped, nil }

func (l *fakeServiceLogger) Error(v ...any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, fmt.Sprint(v...))
	return nil
}

func (l *fakeServiceLogger) Warning(v ...any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warnings = append(l.warnings, fmt.Sprint(v...))
	return nil
}

func (l *fakeServiceLogger) Info(v ...any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, fmt.Sprint(v...))
	return nil
}

func (l *fakeServiceLogger) Errorf(format string, args ...any) error {
	return l.Error(fmt.Sprintf(format, args...))
}

func (l *fakeServiceLogger) Warningf(format string, args ...any) error {
	return l.Warning(fmt.Sprintf(format, args...))
}

func (l *fakeServiceLogger) Infof(format string, args ...any) error {
	return l.Info(fmt.Sprintf(format, args...))
}

func (l *fakeServiceLogger) joinedInfos() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.infos, "\n")
}

func (l *fakeServiceLogger) joinedWarnings() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.warnings, "\n")
}

func (l *fakeServiceLogger) joinedErrors() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.errors, "\n")
}

func (l *fakeServiceLogger) infoCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.infos)
}

func (l *fakeServiceLogger) warningCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.warnings)
}

func (l *fakeServiceLogger) errorCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errors)
}
