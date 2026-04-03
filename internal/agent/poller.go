package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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

// Poller periodically checks the management server for updates.
type Poller struct {
	serverURL   string
	fingerprint string
	dataDir     string
	interval    time.Duration
	logger      *slog.Logger
	signalFunc  func() error // for testing: override SIGHUP sending
}

// NewPoller creates a new Poller.
func NewPoller(serverURL, fingerprint, dataDir string, interval time.Duration, logger *slog.Logger) *Poller {
	return &Poller{
		serverURL:   serverURL,
		fingerprint: fingerprint,
		dataDir:     dataDir,
		interval:    interval,
		logger:      logger,
		signalFunc:  signalNebula,
	}
}

// Run starts the poll loop, blocking until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	p.logger.Info("starting poll loop", "interval", p.interval, "server", p.serverURL)

	ticker := time.NewTicker(p.interval)
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

func (p *Poller) poll(_ context.Context) error {
	url := fmt.Sprintf("%s/api/v1/agent/updates?fingerprint=%s", p.serverURL, p.fingerprint)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("poll request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
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
		if err := os.WriteFile(filepath.Join(p.dataDir, "host.crt"), []byte(*updates.CertificatePEM), 0o644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		p.logger.Info("certificate updated")
		needsReload = true
	}

	if updates.CACertPEM != nil {
		if err := os.WriteFile(filepath.Join(p.dataDir, "ca.crt"), []byte(*updates.CACertPEM), 0o644); err != nil {
			return fmt.Errorf("write CA cert: %w", err)
		}
		p.logger.Info("CA certificate updated")
		needsReload = true
	}

	if updates.ConfigYAML != nil {
		if err := os.WriteFile(filepath.Join(p.dataDir, "config.yml"), []byte(*updates.ConfigYAML), 0o644); err != nil {
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

// signalNebula sends SIGHUP to the nebula process.
func signalNebula() error {
	// Find nebula process by name
	// In production, this would use a PID file or process lookup.
	// For now, try to signal by name using pkill.
	proc, err := os.FindProcess(1) // placeholder
	if err != nil {
		return fmt.Errorf("find nebula process: %w", err)
	}
	return proc.Signal(syscall.SIGHUP)
}
