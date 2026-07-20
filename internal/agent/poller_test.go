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
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/pki"
	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
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

func newTestPoller(t *testing.T, cfg PollerConfig) *Poller {
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
// host.signing.key (consistent with the default chosen by newTestPoller above).
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
	p := newTestPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	})

	var signaled atomic.Bool
	p.signalFunc = func() error {
		signaled.Store(true)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if signaled.Load() {
		t.Error("should not signal nebula when no updates")
	}
}

func TestPoller_WithCertUpdate(t *testing.T) {
	certPEM := validPollerHostCertificate(t)
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
	p := newTestPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	})

	var signaled atomic.Bool
	p.signalFunc = func() error {
		signaled.Store(true)
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

	if !signaled.Load() {
		t.Error("should signal nebula after cert update")
	}
}

func TestPoller_WithCACertUpdate(t *testing.T) {
	caManager, err := pki.NewCA("ca-update-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer caManager.Wipe()
	caPEM, err := caManager.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	caCertPEM := string(caPEM)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: true,
			CACertPEM:  &caCertPEM,
			Blocklist:  []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newTestPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	})

	var signaled atomic.Bool
	p.signalFunc = func() error {
		signaled.Store(true)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	data, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read CA cert: %v", err)
	}
	if string(data) != caCertPEM {
		t.Errorf("CA cert = %q, want %q", string(data), caCertPEM)
	}

	if !signaled.Load() {
		t.Error("should signal nebula after CA cert update")
	}
}

func TestPoller_WithConfigUpdate(t *testing.T) {
	dir := t.TempDir()
	configYAML := "pki:\n  ca: " + filepath.Join(dir, "ca.crt") + "\n  cert: " + filepath.Join(dir, "host.crt") + "\n  key: " + filepath.Join(dir, "host.key") + "\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: true,
			ConfigYAML: &configYAML,
			Blocklist:  []string{},
		})
	}))
	defer server.Close()

	seedSigningKeyAt(t, dir)
	p := newTestPoller(t, PollerConfig{
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

func validPollerHostCertificate(t *testing.T) string {
	t.Helper()
	manager, err := pki.NewCA("poller-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Wipe()
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	defer clear(privateKey)
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := manager.Sign(pki.SignRequest{
		Name: "poller-host", PublicKey: publicKey,
		Networks: []netip.Prefix{netip.MustParsePrefix("10.88.0.2/16")}, Duration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := certificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
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
	p := newTestPoller(t, PollerConfig{
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
	p := newTestPoller(t, PollerConfig{
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
		t.Error("expected error when context is canceled")
	}
}

// TestPoll_HTTPTimeout verifies that a single poll honors the configured
// client timeout even when the request context carries no deadline (the
// daemon case, #193). Before the fix poll() used http.DefaultClient, which
// has no timeout, so an unresponsive-but-connected server hung the loop
// forever.
func TestPoll_HTTPTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never respond until the client gives up
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newTestPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    time.Hour,
		HTTPTimeout: 100 * time.Millisecond,
	})

	// context.Background() never cancels — only the client timeout can bound
	// the call.
	start := time.Now()
	err := p.poll(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error from unresponsive server")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("poll did not honor HTTPTimeout; took %v", elapsed)
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

// TestPoller_RejectsInvalidCACert verifies that a poll response carrying a
// non-CA or malformed certificate is rejected and the on-disk CA file is
// not overwritten (#293 M-1).
func TestPoller_RejectsInvalidCACert(t *testing.T) {
	// A valid host certificate (not a CA) must be rejected.
	hostCertPEM := validPollerHostCertificate(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: true,
			CACertPEM:  &hostCertPEM,
			Blocklist:  []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	// Seed an existing CA file so we can verify it is not overwritten.
	originalCA := []byte("original-ca")
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), originalCA, 0o644); err != nil {
		t.Fatal(err)
	}

	p := newTestPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	data, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(originalCA) {
		t.Errorf("CA file was overwritten with invalid cert; got %q", string(data))
	}
}

// TestSignalNebula_InvalidPID verifies that PID values 0 and -1 are
// rejected before sending SIGHUP (#293 M-5).
func TestSignalNebula_InvalidPID(t *testing.T) {
	for _, pidContent := range []string{"0", "-1", " 0 ", " -1 "} {
		dir := t.TempDir()
		pidFile := filepath.Join(dir, "nebula.pid")
		if err := os.WriteFile(pidFile, []byte(pidContent), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := signalNebulaFromPID(pidFile); err == nil {
			t.Errorf("expected error for PID content %q, got nil", pidContent)
		}
	}
}

// TestPoller_ZeroizesSigningKeyOnShutdown verifies that the signing key
// is zeroed after Run returns (#293 L-2).
func TestPoller_ZeroizesSigningKeyOnShutdown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{HasUpdates: false, Blocklist: []string{}})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newTestPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    50 * time.Millisecond,
	})

	// Capture a reference to the key bytes before Run.
	keyBytes := p.signingKey

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	for i, b := range keyBytes {
		if b != 0 {
			t.Fatalf("signing key byte %d = %d after Run, want 0", i, b)
		}
	}
}
