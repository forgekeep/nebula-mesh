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
func restartPoller(t *testing.T, oldConfig, candidate string, restart func(context.Context) error) (p *Poller, reloads, restarts *int, acked *bool, posts *[]string, status *int) {
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
	posts = new([]string)
	status = new(int)
	*status = http.StatusOK
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			if strings.Contains(r.URL.Path, "config-ack") {
				*acked = true
				return
			}
			*posts = append(*posts, r.URL.Path)
			w.WriteHeader(*status)
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
	return p, reloads, restarts, acked, posts, status
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
	p, reloads, restarts, acked, _, _ := restartPoller(t, restartBaseConfig, changedPort(), func(context.Context) error { return nil })
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *restarts != 1 || *reloads != 0 || !*acked {
		t.Errorf("restarts=%d reloads=%d acked=%v, want 1, 0, true", *restarts, *reloads, *acked)
	}
}

func TestPoll_ReloadableChangeKeepsReload(t *testing.T) {
	candidate := strings.Replace(restartBaseConfig, "inbound: []", "inbound: [{port: any, proto: any, host: any}]", 1)
	p, reloads, restarts, acked, _, _ := restartPoller(t, restartBaseConfig, candidate, func(context.Context) error { return nil })
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *restarts != 0 || *reloads != 1 || !*acked {
		t.Errorf("restarts=%d reloads=%d acked=%v, want 0, 1, true", *restarts, *reloads, *acked)
	}
}

func TestPoll_FirstConfigDoesNotRestart(t *testing.T) {
	p, reloads, restarts, _, _, _ := restartPoller(t, "", changedPort(), func(context.Context) error { return nil })
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *restarts != 0 || *reloads != 1 {
		t.Errorf("restarts=%d reloads=%d, want 0, 1", *restarts, *reloads)
	}
}

func TestPoll_RestartFailureFallsBackToReload(t *testing.T) {
	p, reloads, restarts, acked, _, _ := restartPoller(t, restartBaseConfig, changedPort(), func(context.Context) error { return errors.New("unit failed") })
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *restarts != 1 || *reloads != 1 || !*acked {
		t.Errorf("restarts=%d reloads=%d acked=%v, want 1, 1, true", *restarts, *reloads, *acked)
	}
}

func TestPoll_NoRestartCommandReloads(t *testing.T) {
	p, reloads, _, acked, _, _ := restartPoller(t, restartBaseConfig, changedPort(), nil)
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if *reloads != 1 || !*acked {
		t.Errorf("reloads=%d acked=%v, want 1, true", *reloads, *acked)
	}
}

const (
	restartRequiredPath = "/api/v1/agent/restart-pending/required"
	restartClearedPath  = "/api/v1/agent/restart-pending/cleared"
)

func writePID(t *testing.T, p *Poller, pid string) {
	t.Helper()
	p.config.PIDFile = filepath.Join(p.config.DataDir, "nebula.pid")
	if err := os.WriteFile(p.config.PIDFile, []byte(pid), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPoll_PendingRestartClearsWhenPIDChanges(t *testing.T) {
	p, _, _, _, posts, _ := restartPoller(t, restartBaseConfig, changedPort(), nil)
	writePID(t, p, "4242")

	// First poll writes the config and marks; the second reports; the third,
	// with the same PID, has nothing more to say.
	for range 3 {
		if err := p.PollOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(*posts, []string{restartRequiredPath}) {
		t.Fatalf("posts = %q, want one required report", *posts)
	}

	writePID(t, p, "5151")
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*posts, []string{restartRequiredPath, restartClearedPath}) {
		t.Fatalf("posts = %q, want a cleared report after the PID changed", *posts)
	}
	if _, ok := p.loadRestartState(); ok {
		t.Error("restart state kept after the clear")
	}
}

func TestPoll_PendingRestartSurvivesAgentRestart(t *testing.T) {
	p, _, _, _, posts, _ := restartPoller(t, restartBaseConfig, changedPort(), nil)
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	// A new poller over the same data dir picks the mark up from disk.
	next := newTestPoller(t, p.config)
	if err := next.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(*posts, []string{restartRequiredPath}) {
		t.Fatalf("posts = %q", *posts)
	}
}

func TestPoll_LaterSuccessfulRestartClearsTheMark(t *testing.T) {
	fail := true
	p, _, _, _, posts, _ := restartPoller(t, restartBaseConfig, changedPort(), func(context.Context) error {
		if fail {
			return errors.New("unit failed")
		}
		return nil
	})
	for range 2 {
		if err := p.PollOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(*posts, []string{restartRequiredPath}) {
		t.Fatalf("posts = %q", *posts)
	}

	// The next delivery changes a startup-only key again and the command works.
	fail = false
	old := strings.ReplaceAll(restartBaseConfig, "%DIR%", p.config.DataDir)
	if err := os.WriteFile(p.nebulaConfigPath(), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.PollOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(*posts, []string{restartRequiredPath, restartClearedPath}) {
		t.Fatalf("posts = %q, want cleared after a successful restart", *posts)
	}
}

func TestPoll_RestartReportRetriedThenDroppedOnOldServer(t *testing.T) {
	p, _, _, _, posts, status := restartPoller(t, restartBaseConfig, changedPort(), nil)
	*status = http.StatusInternalServerError
	for range 3 {
		if err := p.PollOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if len(*posts) != 2 {
		t.Fatalf("posts = %q, want a retry on each poll after the mark", *posts)
	}
	if _, ok := p.loadRestartState(); !ok {
		t.Fatal("restart state lost after a failed report")
	}
	*status = http.StatusNotFound
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.loadRestartState(); ok {
		t.Error("restart state kept against a server without the endpoint")
	}
}

// An operator can clear the mark on the server while the agent still holds
// it; the next restart-only change must reach the server again.
func TestPoll_NewChangeReportsAgainOverAReportedMark(t *testing.T) {
	p, _, _, _, posts, _ := restartPoller(t, restartBaseConfig, changedPort(), nil)
	for range 2 {
		if err := p.PollOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	old := strings.ReplaceAll(restartBaseConfig, "%DIR%", p.config.DataDir)
	if err := os.WriteFile(p.nebulaConfigPath(), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := p.PollOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(*posts, []string{restartRequiredPath, restartRequiredPath}) {
		t.Fatalf("posts = %q, want the second change reported too", *posts)
	}
}
