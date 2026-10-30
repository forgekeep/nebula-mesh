package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const restartBaseConfig = `pki:
  ca: %DIR%/ca.crt
  cert: %DIR%/host.crt
  key: %DIR%/host.key
listen:
  port: 4242
firewall:
  inbound: []
`

// restartPoller delivers candidate once over a fake server and counts which
// hook ran.
func restartPoller(t *testing.T, oldConfig, candidate string, restart func(context.Context) error) (p *Poller, reloads, restarts *int, acked *bool) {
	t.Helper()
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	configPath := filepath.Join(dir, "config.yml")
	expand := func(s string) string { return strings.ReplaceAll(s, "%DIR%", dir) }
	if oldConfig != "" {
		if err := os.WriteFile(configPath, []byte(expand(oldConfig)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	body := expand(candidate)
	acked = new(bool)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if strings.Contains(r.URL.Path, "config-ack") {
				*acked = true
			}
			return
		}
		_ = json.NewEncoder(w).Encode(UpdatesResponse{HasUpdates: true, ConfigYAML: &body, ConfigVersion: 3, Blocklist: []string{}})
	}))
	t.Cleanup(server.Close)
	p = newTestPoller(t, PollerConfig{
		ServerURL: server.URL, Fingerprint: "fp", DataDir: dir, Interval: time.Hour,
		NebulaConfigPath: configPath,
		NebulaCAPath:     filepath.Join(dir, "ca.crt"),
		NebulaCertPath:   filepath.Join(dir, "host.crt"),
		NebulaKeyPath:    filepath.Join(dir, "host.key"),
	})
	reloads, restarts = new(int), new(int)
	p.signalFunc = func(context.Context) error { *reloads++; return nil }
	if restart != nil {
		p.restartFunc = func(ctx context.Context) error { *restarts++; return restart(ctx) }
	}
	return p, reloads, restarts, acked
}

func changedPort() string {
	return strings.Replace(restartBaseConfig, "port: 4242", "port: 4243", 1)
}

func TestChangedRestartKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if got := changedRestartKeys(path, "listen:\n  port: 1\n"); got != nil {
		t.Errorf("no old config: %v", got)
	}
	if err := os.WriteFile(path, []byte("listen:\n  port: 1\nrelay:\n  relays: [10.0.0.1]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := changedRestartKeys(path, "listen:\n  port: 1\nrelay:\n  relays: [10.0.0.2]\n"); len(got) != 0 {
		t.Errorf("reloadable change: %v", got)
	}
	got := changedRestartKeys(path, "routines: 2\nlisten:\n  port: 2\n")
	if !slices.Contains(got, "listen.port") || !slices.Contains(got, "routines") {
		t.Errorf("changed keys = %v", got)
	}
	if err := os.WriteFile(path, []byte(": not yaml ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := changedRestartKeys(path, "listen:\n  port: 2\n"); got != nil {
		t.Errorf("unreadable old config: %v", got)
	}
}

func TestPoll_RestartOnlyChangeRunsRestartInsteadOfReload(t *testing.T) {
	p, reloads, restarts, acked := restartPoller(t, restartBaseConfig, changedPort(), func(context.Context) error { return nil })
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *restarts != 1 || *reloads != 0 || !*acked {
		t.Errorf("restarts=%d reloads=%d acked=%v, want 1, 0, true", *restarts, *reloads, *acked)
	}
}

func TestPoll_ReloadableChangeKeepsReload(t *testing.T) {
	candidate := strings.Replace(restartBaseConfig, "inbound: []", "inbound: [{port: any, proto: any, host: any}]", 1)
	p, reloads, restarts, acked := restartPoller(t, restartBaseConfig, candidate, func(context.Context) error { return nil })
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *restarts != 0 || *reloads != 1 || !*acked {
		t.Errorf("restarts=%d reloads=%d acked=%v, want 0, 1, true", *restarts, *reloads, *acked)
	}
}

func TestPoll_FirstConfigDoesNotRestart(t *testing.T) {
	p, reloads, restarts, _ := restartPoller(t, "", changedPort(), func(context.Context) error { return nil })
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *restarts != 0 || *reloads != 1 {
		t.Errorf("restarts=%d reloads=%d, want 0, 1", *restarts, *reloads)
	}
}

func TestPoll_RestartFailureFallsBackToReload(t *testing.T) {
	p, reloads, restarts, acked := restartPoller(t, restartBaseConfig, changedPort(), func(context.Context) error { return errors.New("unit failed") })
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *restarts != 1 || *reloads != 1 || !*acked {
		t.Errorf("restarts=%d reloads=%d acked=%v, want 1, 1, true", *restarts, *reloads, *acked)
	}
}

func TestPoll_NoRestartCommandReloads(t *testing.T) {
	p, reloads, _, acked := restartPoller(t, restartBaseConfig, changedPort(), nil)
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *reloads != 1 || !*acked {
		t.Errorf("reloads=%d acked=%v, want 1, true", *reloads, *acked)
	}
}
