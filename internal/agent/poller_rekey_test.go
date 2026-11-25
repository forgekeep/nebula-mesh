package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/rekeytoken"
)

func TestPoll_ReturnsRekeyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates:      true,
			RekeyRequired:   true,
			EnrollmentToken: "rekey-token-XYZ",
			Blocklist:       []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p, err := NewPoller(PollerConfig{
		ServerURL:      server.URL,
		Fingerprint:    "test-fp",
		DataDir:        dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"),
		Interval:       time.Hour,
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	p.signalFunc = func(context.Context) error { return nil }

	pollErr := p.poll(context.Background())
	if pollErr == nil {
		t.Fatal("poll returned nil; expected RekeyError")
	}
	if !IsRekey(pollErr) {
		t.Fatalf("IsRekey(err) = false; want true, err = %v", pollErr)
	}
	var re *RekeyError
	if !errors.As(pollErr, &re) {
		t.Fatalf("errors.As(*RekeyError) failed for %v", pollErr)
	}
	if re.Token != "rekey-token-XYZ" {
		t.Errorf("Token = %q, want rekey-token-XYZ", re.Token)
	}
}

func TestPoll_RejectsRekeyWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates:    true,
			RekeyRequired: true,
			Blocklist:     []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p, err := NewPoller(PollerConfig{
		ServerURL:      server.URL,
		Fingerprint:    "test-fp",
		DataDir:        dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"),
		Interval:       time.Hour,
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	p.signalFunc = func(context.Context) error { return nil }

	err = p.poll(context.Background())
	if err == nil {
		t.Fatal("expected error when rekey_required but token is empty")
	}
	if IsRekey(err) {
		t.Errorf("missing token should not yield RekeyError; got %v", err)
	}
}

func TestRun_StopsOnRekey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates:      true,
			RekeyRequired:   true,
			EnrollmentToken: "tok",
			Blocklist:       []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newTestPoller(t, PollerConfig{
		ServerURL:      server.URL,
		Fingerprint:    "test-fp",
		DataDir:        dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"),
		Interval:       20 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	runErr := p.Run(ctx)
	if !IsRekey(runErr) {
		t.Errorf("Run did not propagate rekey; got %v", runErr)
	}
}

func TestPoll_DecryptsRekeyToken(t *testing.T) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := rekeytoken.Seal(publicKey, "rekey-token-XYZ")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			RekeyRequired: true, EnrollmentTokenEncrypted: sealed, Blocklist: []string{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "host.key"), cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, privateKey), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newTestPoller(t, PollerConfig{ServerURL: server.URL, DataDir: dir, Interval: time.Hour})
	pollErr := p.poll(context.Background())
	var re *RekeyError
	if !errors.As(pollErr, &re) {
		t.Fatalf("poll error = %v, want RekeyError", pollErr)
	}
	if re.Token != "rekey-token-XYZ" {
		t.Fatalf("decrypted token = %q", re.Token)
	}
}

func TestPoll_RejectsWrongRekeyKey(t *testing.T) {
	privateKey := make([]byte, curve25519.ScalarSize)
	otherKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := rekeytoken.Seal(publicKey, "rekey-token-XYZ")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{RekeyRequired: true, EnrollmentTokenEncrypted: sealed})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "host.key"), cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, otherKey), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newTestPoller(t, PollerConfig{ServerURL: server.URL, DataDir: dir, Interval: time.Hour})
	if err := p.poll(context.Background()); err == nil || IsRekey(err) {
		t.Fatalf("wrong Nebula key produced a rekey credential: %v", err)
	}
}

func TestPoll_RejectsAmbiguousRekeyToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			RekeyRequired: true, EnrollmentToken: "plaintext", EnrollmentTokenEncrypted: "ciphertext",
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newTestPoller(t, PollerConfig{ServerURL: server.URL, DataDir: dir, Interval: time.Hour})
	if err := p.poll(context.Background()); err == nil || IsRekey(err) {
		t.Fatalf("ambiguous rekey response produced a credential: %v", err)
	}
}
