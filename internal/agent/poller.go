package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// UpdatesResponse is the response from the agent updates endpoint.
type UpdatesResponse struct {
	HasUpdates     bool     `json:"has_updates"`
	CertificatePEM *string  `json:"certificate_pem,omitempty"`
	CACertPEM      *string  `json:"ca_certificate_pem,omitempty"`
	ConfigYAML     *string  `json:"config_yaml,omitempty"`
	Blocklist      []string `json:"blocklist"`
}

// PollerConfig holds configuration for the Poller.
type PollerConfig struct {
	ServerURL   string
	Fingerprint string
	DataDir     string
	Interval    time.Duration
	PIDFile     string
}

// Poller periodically checks the management server for updates.
type Poller struct {
	config     PollerConfig
	logger     *slog.Logger
	signalFunc func() error // for testing: override SIGHUP sending
}

// NewPoller creates a new Poller.
func NewPoller(cfg PollerConfig, logger *slog.Logger) *Poller {
	p := &Poller{
		config: cfg,
		logger: logger,
	}
	p.signalFunc = func() error {
		return signalNebulaFromPID(cfg.PIDFile)
	}
	return p
}

// Run starts the poll loop, blocking until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	p.logger.Info("starting poll loop", "interval", p.config.Interval, "server", p.config.ServerURL)

	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("poll loop stopped")
			return ctx.Err()
		case <-ticker.C:
			if err := p.poll(ctx); err != nil {
				p.logger.Error("poll failed", "error", err)
			}
		}
	}
}

func (p *Poller) poll(ctx context.Context) error {
	u := fmt.Sprintf("%s/api/v1/agent/updates?fingerprint=%s", p.config.ServerURL, url.QueryEscape(p.config.Fingerprint))
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return fmt.Errorf("create poll request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("poll request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error("close response body", "error", err)
		}
	}()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("poll failed (HTTP %d, body unreadable: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("poll failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var updates UpdatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&updates); err != nil {
		return fmt.Errorf("decode updates: %w", err)
	}

	if !updates.HasUpdates {
		return nil
	}

	needsReload := false

	if updates.CertificatePEM != nil {
		if err := atomicWriteFile(filepath.Join(p.config.DataDir, "host.crt"), []byte(*updates.CertificatePEM), 0o644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		p.logger.Info("certificate updated")
		needsReload = true
	}

	if updates.CACertPEM != nil {
		if err := atomicWriteFile(filepath.Join(p.config.DataDir, "ca.crt"), []byte(*updates.CACertPEM), 0o644); err != nil {
			return fmt.Errorf("write CA cert: %w", err)
		}
		p.logger.Info("CA certificate updated")
		needsReload = true
	}

	if updates.ConfigYAML != nil {
		if err := atomicWriteFile(filepath.Join(p.config.DataDir, "config.yml"), []byte(*updates.ConfigYAML), 0o644); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
		p.logger.Info("config updated")
		needsReload = true
	}

	if needsReload {
		if err := p.signalFunc(); err != nil {
			p.logger.Warn("failed to signal nebula", "error", err)
		} else {
			p.logger.Info("nebula reloaded")
		}
	}

	return nil
}

// atomicWriteFile writes data to a temp file, syncs it, then renames to the target path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// cleanup removes temp file on failure; set to nil after successful rename
	cleanup := func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			slog.Error("remove temp file", "path", tmpPath, "error", removeErr)
		}
	}

	if _, err := tmp.Write(data); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			slog.Error("close temp file after write error", "path", tmpPath, "error", closeErr)
		}
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			slog.Error("close temp file after sync error", "path", tmpPath, "error", closeErr)
		}
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename temp to target: %w", err)
	}
	return nil
}

// signalNebulaFromPID reads the PID from file and sends SIGHUP to the nebula process.
func signalNebulaFromPID(pidFile string) error {
	if pidFile == "" {
		return fmt.Errorf("nebula PID file not configured")
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("read PID file %s: %w", pidFile, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("parse PID from %s: %w", pidFile, err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	return proc.Signal(syscall.SIGHUP)
}
