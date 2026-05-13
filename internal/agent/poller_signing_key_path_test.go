package agent

import (
	"log/slog"
	"path/filepath"
	"testing"
)

// TestNewPoller_LoadsFromExplicitSigningKeyPath confirms that the poller
// reads the Ed25519 signing key from PollerConfig.SigningKeyPath rather than
// from DataDir/host.signing.key. #88 separates the agent's own secret from
// Nebula's data dir.
func TestNewPoller_LoadsFromExplicitSigningKeyPath(t *testing.T) {
	dataDir := t.TempDir()
	agentDir := t.TempDir()
	signingKeyPath := filepath.Join(agentDir, "host.signing.key")
	writeSigningKey(t, signingKeyPath)

	p, err := NewPoller(PollerConfig{
		ServerURL:      "http://example.invalid",
		Fingerprint:    "test-fp",
		DataDir:        dataDir,
		SigningKeyPath: signingKeyPath,
	}, slog.Default())
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	if p == nil {
		t.Fatal("nil poller")
	}
}

// TestNewPoller_RequiresSigningKeyPath confirms NewPoller rejects an empty
// SigningKeyPath instead of silently falling back to DataDir/host.signing.key
// (which would re-introduce the concern leak #88 fixes).
func TestNewPoller_RequiresSigningKeyPath(t *testing.T) {
	if _, err := NewPoller(PollerConfig{DataDir: t.TempDir()}, slog.Default()); err == nil {
		t.Fatal("expected error when SigningKeyPath is empty")
	}
}
