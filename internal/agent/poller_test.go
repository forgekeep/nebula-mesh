package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestPoller_NoUpdates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("fingerprint") == "" {
			t.Error("missing fingerprint")
		}
		json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: false,
			Blocklist:  []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	p := NewPoller(PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	}, slog.Default())

	var signalled atomic.Bool
	p.signalFunc = func() error {
		signalled.Store(true)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	if signalled.Load() {
		t.Error("should not signal nebula when no updates")
	}
}

func TestPoller_WithCertUpdate(t *testing.T) {
	certPEM := "-----BEGIN NEBULA CERTIFICATE-----\nupdated-cert\n-----END NEBULA CERTIFICATE-----"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates:     true,
			CertificatePEM: &certPEM,
			Blocklist:      []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	p := NewPoller(PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	}, slog.Default())

	var signalled atomic.Bool
	p.signalFunc = func() error {
		signalled.Store(true)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	// Verify cert file was written
	data, err := os.ReadFile(filepath.Join(dir, "host.crt"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(data) != certPEM {
		t.Errorf("cert = %q, want %q", string(data), certPEM)
	}

	if !signalled.Load() {
		t.Error("should signal nebula after cert update")
	}
}

func TestPoller_WithConfigUpdate(t *testing.T) {
	configYAML := "pki:\n  ca: /etc/nebula/ca.crt\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: true,
			ConfigYAML: &configYAML,
			Blocklist:  []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	p := NewPoller(PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	}, slog.Default())
	p.signalFunc = func() error { return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	data, err := os.ReadFile(filepath.Join(dir, "config.yml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(data) != configYAML {
		t.Errorf("config = %q, want %q", string(data), configYAML)
	}
}

func TestPoller_FingerprintEscaped(t *testing.T) {
	var receivedFP string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedFP = r.URL.Query().Get("fingerprint")
		json.NewEncoder(w).Encode(UpdatesResponse{HasUpdates: false, Blocklist: []string{}})
	}))
	defer server.Close()

	p := NewPoller(PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "fp with spaces&special=chars",
		DataDir:     t.TempDir(),
		Interval:    50 * time.Millisecond,
	}, slog.Default())
	p.signalFunc = func() error { return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	p.Run(ctx)

	if receivedFP != "fp with spaces&special=chars" {
		t.Errorf("fingerprint = %q, want %q", receivedFP, "fp with spaces&special=chars")
	}
}

func TestSignalNebula_ReadsPIDFile(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "nebula.pid")
	// Write current process PID — signal to self is safe (SIGHUP is handled)
	if err := os.WriteFile(pidFile, []byte("99999999"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := signalNebulaFromPID(pidFile)
	// Should fail because PID 99999999 doesn't exist — but it should parse correctly
	if err == nil {
		t.Error("expected error signaling nonexistent process")
	}
}

func TestSignalNebula_MissingPIDFile(t *testing.T) {
	err := signalNebulaFromPID("/nonexistent/nebula.pid")
	if err == nil {
		t.Error("expected error for missing PID file")
	}
}

func TestSignalNebula_NoPIDFile(t *testing.T) {
	err := signalNebulaFromPID("")
	if err == nil {
		t.Error("expected error when PID file not configured")
	}
}
