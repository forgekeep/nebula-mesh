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
	var receivedFP atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedFP.Store(r.URL.Query().Get("fingerprint"))
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

	got, _ := receivedFP.Load().(string)
	if got != "fp with spaces&special=chars" {
		t.Errorf("fingerprint = %q, want %q", got, "fp with spaces&special=chars")
	}
}

func TestPoll_RespectsContext(t *testing.T) {
	// Server that blocks until request is cancelled
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	p := NewPoller(PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     t.TempDir(),
		Interval:    time.Hour, // won't tick — we call poll directly
	}, slog.Default())
	p.signalFunc = func() error { return nil }

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := p.poll(ctx)
	if err == nil {
		t.Error("expected error when context is cancelled")
	}
}

func TestAtomicWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	// Write initial content
	if err := atomicWriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Errorf("content = %q, want hello", data)
	}

	// Overwrite
	if err := atomicWriteFile(path, []byte("world"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "world" {
		t.Errorf("content = %q, want world", data)
	}

	// Verify no temp files left
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file in dir, got %d", len(entries))
	}
}

func TestAtomicWriteFile_InvalidDir(t *testing.T) {
	err := atomicWriteFile("/nonexistent/dir/file.txt", []byte("data"), 0o644)
	if err == nil {
		t.Error("expected error for nonexistent dir")
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
