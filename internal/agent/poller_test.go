package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	corepop "github.com/juev/nebula-mesh/internal/pop"
)

// writeSigningKey writes a freshly generated Ed25519 private key to the
// given path in the on-disk PEM format the poller expects. Returns the
// matching public key so tests can verify signatures. The parent directory
// must already exist.
func writeSigningKey(t *testing.T, path string) ed25519.PublicKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: SigningPrivateKeyPEMType, Bytes: priv})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return pub
}

func newPoller(t *testing.T, cfg PollerConfig) *Poller {
	t.Helper()
	if cfg.SigningKeyPath == "" {
		// Default: put the signing key in a sibling dir to DataDir so tests
		// that pre-write a signing key with writeSigningKey-on-DataDir
		// continue to find it through the legacy code path. The cleaner
		// fixture (signing key outside DataDir) is exercised by
		// TestNewPoller_LoadsFromExplicitSigningKeyPath.
		cfg.SigningKeyPath = filepath.Join(cfg.DataDir, "host.signing.key")
	}
	p, err := NewPoller(cfg, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	p.signalFunc = func() error { return nil }
	return p
}

// seedSigningKeyAt is a convenience helper for tests that don't care where
// the signing key lives — it writes one into the given DataDir's
// host.signing.key (consistent with the default chosen by newPoller above).
func seedSigningKeyAt(t *testing.T, dataDir string) {
	t.Helper()
	writeSigningKey(t, filepath.Join(dataDir, "host.signing.key"))
}

func TestPoller_NoUpdates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(corepop.HeaderFingerprint) == "" {
			t.Error("missing fingerprint header")
		}
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: false,
			Blocklist:  []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	})

	var signalled atomic.Bool
	p.signalFunc = func() error {
		signalled.Store(true)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if signalled.Load() {
		t.Error("should not signal nebula when no updates")
	}
}

func TestPoller_WithCertUpdate(t *testing.T) {
	certPEM := "-----BEGIN NEBULA CERTIFICATE-----\nupdated-cert\n-----END NEBULA CERTIFICATE-----"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates:     true,
			CertificatePEM: &certPEM,
			Blocklist:      []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	})

	var signalled atomic.Bool
	p.signalFunc = func() error {
		signalled.Store(true)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

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
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: true,
			ConfigYAML: &configYAML,
			Blocklist:  []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	data, err := os.ReadFile(filepath.Join(dir, "config.yml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if string(data) != configYAML {
		t.Errorf("config = %q, want %q", string(data), configYAML)
	}
}

func TestPoller_SignsRequest(t *testing.T) {
	var (
		seenFP        atomic.Value
		seenTimestamp atomic.Value
		seenNonces    [2]atomic.Value
		call          atomic.Int32
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenFP.Store(r.Header.Get(corepop.HeaderFingerprint))
		seenTimestamp.Store(r.Header.Get(corepop.HeaderTimestamp))
		idx := call.Add(1) - 1
		if idx < int32(len(seenNonces)) {
			seenNonces[idx].Store(r.Header.Get(corepop.HeaderNonce))
		}
		if r.Header.Get(corepop.HeaderSignature) == "" {
			t.Error("missing signature header")
		}
		_ = json.NewEncoder(w).Encode(UpdatesResponse{HasUpdates: false, Blocklist: []string{}})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "fp-123",
		DataDir:     dir,
		Interval:    20 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if call.Load() < 2 {
		t.Fatalf("expected at least 2 polls, got %d", call.Load())
	}
	if seenFP.Load().(string) != "fp-123" {
		t.Errorf("fingerprint header = %q, want fp-123", seenFP.Load())
	}
	if seenTimestamp.Load().(string) == "" {
		t.Error("missing timestamp")
	}
	if seenNonces[0].Load() == seenNonces[1].Load() {
		t.Errorf("expected distinct nonces, got %v twice", seenNonces[0].Load())
	}
}

func TestPoll_RespectsContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
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
	if err := os.WriteFile(pidFile, []byte("99999999"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := signalNebulaFromPID(pidFile)
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

func TestNewPoller_MissingSigningKey(t *testing.T) {
	if _, err := NewPoller(PollerConfig{DataDir: t.TempDir()}, slog.Default()); err == nil {
		t.Fatal("expected error when host.signing.key missing")
	}
}
