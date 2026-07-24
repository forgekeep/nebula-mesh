package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNebulaReloader_CommandRuns(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix shell test")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	reload := nebulaReloader("touch "+marker, "")
	if err := reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("command did not run: %v", err)
	}
}

func TestNebulaReloader_CommandFailureIncludesOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix shell test")
	}
	reload := nebulaReloader("echo boom-detail >&2; exit 3", "")
	err := reload()
	if err == nil {
		t.Fatal("expected error from failing command")
	}
	if !strings.Contains(err.Error(), "boom-detail") {
		t.Errorf("error %q should include command output", err)
	}
}

func TestNebulaReloader_CommandTimesOut(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix shell test")
	}
	orig := reloadCommandTimeout
	reloadCommandTimeout = 200 * time.Millisecond
	defer func() { reloadCommandTimeout = orig }()

	reload := nebulaReloader("sleep 5", "")
	start := time.Now()
	err := reload()
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("reload took %v, should have been killed by the %v timeout", elapsed, reloadCommandTimeout)
	}
}

// TestNebulaReloader_CommandTakesPrecedenceOverPIDFile: with both settings
// present the command wins — the PID file must not even be read (a bogus
// path would otherwise error).
func TestNebulaReloader_CommandTakesPrecedenceOverPIDFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix shell test")
	}
	reload := nebulaReloader("true", "/nonexistent/nebula.pid")
	if err := reload(); err != nil {
		t.Errorf("command should take precedence over pid file: %v", err)
	}
}

// TestNebulaReloader_FallsBackToPIDFile: without a command the existing
// SIGHUP path is used, including its "not configured" error for an empty
// pid file.
func TestNebulaReloader_FallsBackToPIDFile(t *testing.T) {
	reload := nebulaReloader("", "")
	err := reload()
	if err == nil {
		t.Fatal("expected 'not configured' error with no command and no pid file")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("err = %v, want the signalNebulaFromPID 'not configured' error", err)
	}
}

func reloadTestServer(t *testing.T, dir string, acked *atomic.Bool) *httptest.Server {
	t.Helper()
	configYAML := "pki:\n  ca: " + filepath.Join(dir, "ca.crt") + "\n  cert: " + filepath.Join(dir, "host.crt") + "\n  key: " + filepath.Join(dir, "host.key") + "\n"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/agent/config-ack/") {
			acked.Store(true)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(UpdatesResponse{
			HasUpdates:    true,
			ConfigYAML:    &configYAML,
			ConfigVersion: 7,
			Blocklist:     []string{},
		})
	}))
}

func newReloadCommandPoller(t *testing.T, serverURL, dir, command string) *Poller {
	t.Helper()
	p, err := NewPoller(PollerConfig{
		ServerURL:      serverURL,
		Fingerprint:    "test-fp",
		DataDir:        dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"),
		Interval:       50 * time.Millisecond,
		ReloadCommand:  command,
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestPoller_ReloadCommandFailure_BlocksAck: with nebula_reload_command
// configured, a failing command must behave like a failed SIGHUP with a
// configured pid file — the config version is NOT acknowledged so the
// agent retries the reload on the next poll.
func TestPoller_ReloadCommandFailure_BlocksAck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix shell test")
	}
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	var acked atomic.Bool
	server := reloadTestServer(t, dir, &acked)
	defer server.Close()

	// NewPoller directly: newTestPoller would replace signalFunc with a
	// no-op, and this test needs the real command-backed reloader.
	p := newReloadCommandPoller(t, server.URL, dir, "exit 1")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if acked.Load() {
		t.Error("config must NOT be acked when nebula_reload_command fails")
	}
}

// TestPoller_ReloadCommandSuccess_Acks: the happy path — the command runs,
// the config is acknowledged.
func TestPoller_ReloadCommandSuccess_Acks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix shell test")
	}
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	var acked atomic.Bool
	server := reloadTestServer(t, dir, &acked)
	defer server.Close()

	p := newReloadCommandPoller(t, server.URL, dir, "true")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if !acked.Load() {
		t.Error("config should be acked when nebula_reload_command succeeds")
	}
}

// TestReenrollReload_Selection: re-enroll uses the same precedence — the
// command (when set) wins over the pid-file SIGHUP seam; with neither, no
// reload hook is installed.
func TestReenrollReload_Selection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix shell test")
	}
	marker := filepath.Join(t.TempDir(), "ran")
	var signaledPID string
	seam := func(pidFile string) error { signaledPID = pidFile; return nil }

	reload := reenrollReload(ReenrollOptions{ReloadCommand: "touch " + marker, PIDFile: "/run/nebula.pid"}, seam)
	if reload == nil {
		t.Fatal("reload hook should be set when command is configured")
	}
	if err := reload(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("command did not run")
	}
	if signaledPID != "" {
		t.Error("SIGHUP seam must not be called when command is set")
	}

	reload = reenrollReload(ReenrollOptions{PIDFile: "/run/nebula.pid"}, seam)
	if err := reload(); err != nil {
		t.Fatal(err)
	}
	if signaledPID != "/run/nebula.pid" {
		t.Errorf("signaled pid file = %q, want /run/nebula.pid", signaledPID)
	}

	if reload = reenrollReload(ReenrollOptions{}, seam); reload != nil {
		t.Error("no command and no pid file should install no reload hook")
	}
}
