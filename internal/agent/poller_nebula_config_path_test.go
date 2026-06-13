package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPoller_WritesConfigToNebulaConfigPath is the #224 regression: when a
// custom NebulaConfigPath is set, a config update must land at that path, not
// at DataDir/config.yml. Before the fix the poller wrote DataDir/config.yml
// unconditionally and silently ignored the configured path.
func TestPoller_WritesConfigToNebulaConfigPath(t *testing.T) {
	rendered := "pki:\n  cert: /etc/nebula/host.crt\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: true,
			ConfigYAML: &rendered,
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	customDir := t.TempDir()
	customPath := filepath.Join(customDir, "nebula.yml")

	p := newTestPoller(t, PollerConfig{
		ServerURL:        server.URL,
		Fingerprint:      "test-fp",
		DataDir:          dir,
		NebulaConfigPath: customPath,
		Interval:         time.Hour, // immediate poll on Run is enough
	})
	p.signalFunc = func() error { return nil } // no real Nebula to SIGHUP

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if _, err := os.Stat(customPath); err != nil {
		t.Fatalf("rendered config not written to NebulaConfigPath %s: %v", customPath, err)
	}
	got, err := os.ReadFile(customPath) // #nosec G304 -- test-controlled path
	if err != nil {
		t.Fatalf("read custom config: %v", err)
	}
	if string(got) != rendered {
		t.Errorf("custom config content = %q, want %q", got, rendered)
	}
	// It must NOT have been written to the legacy DataDir/config.yml.
	if _, err := os.Stat(filepath.Join(dir, "config.yml")); err == nil {
		t.Error("config was also written to DataDir/config.yml; NebulaConfigPath was ignored")
	}
}

// TestPoller_NebulaConfigPathFallback covers the empty-path default: the
// rendered config lands at DataDir/config.yml for backward compatibility.
func TestPoller_NebulaConfigPathFallback(t *testing.T) {
	rendered := "static_host_map: {}\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates: true,
			ConfigYAML: &rendered,
		})
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
	p.signalFunc = func() error { return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if _, err := os.Stat(filepath.Join(dir, "config.yml")); err != nil {
		t.Fatalf("rendered config not written to default DataDir/config.yml: %v", err)
	}
}
