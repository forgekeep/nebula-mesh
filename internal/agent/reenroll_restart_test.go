package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// reenrollCase re-enrolls a host whose config on disk ends in oldTail with one
// ending in newTail, and reports how many reloads and acks it took.
func reenrollCase(t *testing.T, oldTail, newTail string, options ReenrollOptions) (dataDir string, reloads, acks int, err error) {
	t.Helper()
	root := t.TempDir()
	profile := models.AgentProfile{
		NebulaConfigPath: filepath.Join(root, "nebula.yml"), NebulaCAPath: filepath.Join(root, "root.pem"),
		NebulaCertPath: filepath.Join(root, "node.pem"), NebulaKeyPath: filepath.Join(root, "node.key"), ConfigAckV1: true,
	}
	base := profileConfigYAML(profile)
	if err := os.WriteFile(profile.NebulaConfigPath, []byte(base+oldTail), 0o600); err != nil {
		t.Fatal(err)
	}
	certPEM, caPEM := testEnrollCerts(t)
	var acknowledgements atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll":
			_ = json.NewEncoder(w).Encode(EnrollResponse{
				CertificatePEM: certPEM, CACertificatePEM: caPEM, ConfigYAML: base + newTail, ConfigVersion: 7,
			})
		case "/api/v1/agent/config-ack/7":
			acknowledgements.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	dataDir = t.TempDir()
	options.DataDir = dataDir
	options.SigningKeyPath = filepath.Join(root, "signing.key")
	options.Profile = profile
	err = reenrollWithSignal(context.Background(), server.URL, "token", options, func(string) error {
		reloads++
		return nil
	})
	return dataDir, reloads, int(acknowledgements.Load()), err
}

func hasRestartMark(dataDir string) bool {
	_, err := os.Stat(filepath.Join(dataDir, restartStateFile))
	return err == nil
}

const (
	routinesOne  = "routines: 1\n"
	routinesFour = "routines: 4\n"
)

func TestReenroll_StartupKeyChangeRunsRestartCommand(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "restarted")
	dataDir, reloads, acks, err := reenrollCase(t, routinesOne, routinesFour, ReenrollOptions{
		PIDFile: "/run/nebula.pid", RestartCommand: scriptTouch(marker),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("restart command did not run: %v", err)
	}
	if reloads != 0 || acks != 1 || hasRestartMark(dataDir) {
		t.Errorf("reloads=%d acks=%d mark=%v, want 0, 1, false", reloads, acks, hasRestartMark(dataDir))
	}
}

func TestReenroll_StartupKeyChangeWithoutCommandMarksRestart(t *testing.T) {
	dataDir, reloads, acks, err := reenrollCase(t, routinesOne, routinesFour, ReenrollOptions{PIDFile: "/run/nebula.pid"})
	if err != nil {
		t.Fatal(err)
	}
	if reloads != 1 || acks != 1 || !hasRestartMark(dataDir) {
		t.Errorf("reloads=%d acks=%d mark=%v, want 1, 1, true", reloads, acks, hasRestartMark(dataDir))
	}
}

// The mark must reach the server: the poller that takes over after the rekey
// reports what re-enrollment left in the data dir.
func TestReenroll_MarkIsReportedByTheNextPoll(t *testing.T) {
	dataDir, _, _, err := reenrollCase(t, routinesOne, routinesFour, ReenrollOptions{PIDFile: "/run/nebula.pid"})
	if err != nil {
		t.Fatal(err)
	}
	var reported atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == restartRequiredPath {
			reported.Store(true)
			return
		}
		_ = json.NewEncoder(w).Encode(UpdatesResponse{Blocklist: []string{}})
	}))
	t.Cleanup(server.Close)
	seedSigningKeyAt(t, dataDir)
	p := newTestPoller(t, PollerConfig{ServerURL: server.URL, Fingerprint: "fp", DataDir: dataDir})
	if err := p.PollOnce(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !reported.Load() {
		t.Error("the poll after re-enrollment did not report the pending restart")
	}
}

func TestReenroll_FailingRestartCommandDoesNotAbort(t *testing.T) {
	dataDir, reloads, acks, err := reenrollCase(t, routinesOne, routinesFour, ReenrollOptions{
		PIDFile: "/run/nebula.pid", RestartCommand: "exit 1",
	})
	if err != nil {
		t.Fatalf("a failing restart command must not abort the re-enrollment: %v", err)
	}
	if reloads != 1 || acks != 1 || !hasRestartMark(dataDir) {
		t.Errorf("reloads=%d acks=%d mark=%v, want 1, 1, true", reloads, acks, hasRestartMark(dataDir))
	}
}

func TestReenroll_ReloadableChangeKeepsReload(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "restarted")
	dataDir, reloads, acks, err := reenrollCase(t, routinesOne+"relay:\n  relays: [10.0.0.1]\n", routinesOne+"relay:\n  relays: [10.0.0.2]\n", ReenrollOptions{
		PIDFile: "/run/nebula.pid", RestartCommand: scriptTouch(marker),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("restart command ran for a reloadable change")
	}
	if reloads != 1 || acks != 1 || hasRestartMark(dataDir) {
		t.Errorf("reloads=%d acks=%d mark=%v, want 1, 1, false", reloads, acks, hasRestartMark(dataDir))
	}
}

func TestReenroll_NoReloadHookStillMarksRestart(t *testing.T) {
	dataDir, reloads, acks, err := reenrollCase(t, routinesOne, routinesFour, ReenrollOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if reloads != 0 || acks != 1 || !hasRestartMark(dataDir) {
		t.Errorf("reloads=%d acks=%d mark=%v, want 0, 1, true", reloads, acks, hasRestartMark(dataDir))
	}
}
