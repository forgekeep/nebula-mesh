package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestPoll_ReturnsRevocationErrorOn403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason":"revoked","blocked_at":"2026-05-13T00:00:00Z"}`))
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
	p.signalFunc = func() error { return nil }

	pollErr := p.poll(context.Background())
	if pollErr == nil {
		t.Fatal("poll returned nil; expected RevocationError")
	}
	if !IsRevoked(pollErr) {
		t.Fatalf("IsRevoked(err) = false; want true, err = %v", pollErr)
	}
	var re *RevocationError
	if !errors.As(pollErr, &re) {
		t.Fatalf("errors.As(*RevocationError) failed for %v", pollErr)
	}
	if re.StatusCode != http.StatusForbidden || re.Reason != "revoked" {
		t.Errorf("got %+v, want 403/revoked", re)
	}
}

func TestPoll_ReturnsRevocationErrorOn410(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = w.Write([]byte(`{"reason":"import_canceled"}`))
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
	p.signalFunc = func() error { return nil }

	pollErr := p.poll(context.Background())
	if !IsRevoked(pollErr) {
		t.Fatalf("IsRevoked(err) = false; want true, err = %v", pollErr)
	}
	var re *RevocationError
	if !errors.As(pollErr, &re) || re.Reason != "import_canceled" {
		t.Fatalf("reason = %#v, want import_canceled", re)
	}
}

func TestRun_StopsOnRevocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason":"revoked"}`))
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
	if !IsRevoked(runErr) {
		t.Errorf("Run did not propagate revocation; got %v", runErr)
	}
}
