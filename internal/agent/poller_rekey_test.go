package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
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
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"),
		Interval:    time.Hour,
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	p.signalFunc = func() error { return nil }

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
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"),
		Interval:    time.Hour,
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	p.signalFunc = func() error { return nil }

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
	p := newPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"),
		Interval:    20 * time.Millisecond,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	runErr := p.Run(ctx)
	if !IsRekey(runErr) {
		t.Errorf("Run did not propagate rekey; got %v", runErr)
	}
}
