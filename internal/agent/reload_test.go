package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNebulaReloader_CommandRuns(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	reload := nebulaReloader(scriptTouch(marker), "")
	if err := reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("command did not run: %v", err)
	}
}

func TestNebulaReloader_CommandFailureIncludesOutput(t *testing.T) {
	reload := nebulaReloader(scriptFailNoisily, "")
	err := reload(context.Background())
	if err == nil {
		t.Fatal("expected error from failing command")
	}
	if !strings.Contains(err.Error(), "boom-detail") {
		t.Errorf("error %q should include command output", err)
	}
}

func TestNebulaReloader_CommandTimesOut(t *testing.T) {
	shrinkReloadTimeout(t, 200*time.Millisecond, 500*time.Millisecond)

	reload := nebulaReloader(scriptSleepLong, "")
	start := time.Now()
	err := reload(context.Background())
	if err == nil {
		t.Fatal("expected timeout error")
	}
	// scriptSleepLong runs for a minute. The budget is loose enough to
	// absorb a slow terminator (Windows shells out to taskkill) and still
	// an order of magnitude short of "waited for the command".
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("reload took %v, should have been killed by the %v timeout", elapsed, reloadCommandTimeout)
	}
}

// TestNebulaReloader_CapsCommandOutput: a hook that floods its output must
// not grow the agent's heap without bound. The error keeps the head of the
// output and says how much it dropped.
func TestNebulaReloader_CapsCommandOutput(t *testing.T) {
	err := nebulaReloader(scriptFlood, "")(context.Background())
	if err == nil {
		t.Fatal("expected error from failing command")
	}
	// Generous slack over the cap for the error's own prose; the point is
	// that the message is bounded rather than proportional to the flood.
	if got, limit := len(err.Error()), reloadCommandOutputLimit+1024; got > limit {
		t.Errorf("error message is %d bytes, want at most %d — output is not capped", got, limit)
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Errorf("error %q should say that output was truncated", err)
	}
}

// TestNebulaReloader_CommandTakesPrecedenceOverPIDFile: with both settings
// present the command wins — the PID file must not even be read (a bogus
// path would otherwise error).
func TestNebulaReloader_CommandTakesPrecedenceOverPIDFile(t *testing.T) {
	reload := nebulaReloader(scriptSucceed, "/nonexistent/nebula.pid")
	if err := reload(context.Background()); err != nil {
		t.Errorf("command should take precedence over pid file: %v", err)
	}
}

// TestNebulaReloader_FallsBackToPIDFile: without a command the existing
// SIGHUP path is used, including its "not configured" error for an empty
// pid file.
func TestNebulaReloader_FallsBackToPIDFile(t *testing.T) {
	reload := nebulaReloader("", "")
	err := reload(context.Background())
	if err == nil {
		t.Fatal("expected 'not configured' error with no command and no pid file")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("err = %v, want the signalNebulaFromPID 'not configured' error", err)
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{limit: 8}

	// Short of the cap: verbatim, no note.
	if n, err := b.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("Write = (%d, %v), want (3, nil)", n, err)
	}
	if got := b.String(); got != "abc" {
		t.Errorf("String() = %q, want %q", got, "abc")
	}

	// Straddling the cap: the head is kept, the overflow only counted.
	// Write must still report every byte consumed, or os/exec's copier
	// treats the short write as an error and tears down the pipe.
	if n, err := b.Write([]byte("defghijkl")); n != 9 || err != nil {
		t.Fatalf("Write = (%d, %v), want (9, nil)", n, err)
	}
	// Past the cap entirely: still accepted, still only counted.
	if n, err := b.Write([]byte("mno")); n != 3 || err != nil {
		t.Fatalf("Write = (%d, %v), want (3, nil)", n, err)
	}

	got := b.String()
	if !strings.HasPrefix(got, "abcdefgh") {
		t.Errorf("String() = %q, want it to start with the first 8 bytes", got)
	}
	if !strings.Contains(got, "7 more bytes truncated") {
		t.Errorf("String() = %q, want it to report the 7 dropped bytes", got)
	}
}

// shrinkReloadTimeout rescales the reload budget for tests and restores it
// afterwards.
func shrinkReloadTimeout(t *testing.T, timeout, waitDelay time.Duration) {
	t.Helper()
	origTimeout, origDelay := reloadCommandTimeout, reloadCommandWaitDelay
	reloadCommandTimeout, reloadCommandWaitDelay = timeout, waitDelay
	t.Cleanup(func() {
		reloadCommandTimeout, reloadCommandWaitDelay = origTimeout, origDelay
	})
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

// waitForAck blocks until acked is set, mirroring waitForFile. The happy-path
// reload test observes the ack this way rather than asserting after a fixed
// interval, so it does not care how long a slow runner takes to deliver it.
func waitForAck(t *testing.T, acked *atomic.Bool, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if acked.Load() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("config was not acked within %v", within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPoller_ReloadCommandFailure_BlocksAck: with nebula_reload_command
// configured, a failing command must behave like a failed SIGHUP with a
// configured pid file — the config version is NOT acknowledged so the
// agent retries the reload on the next poll.
func TestPoller_ReloadCommandFailure_BlocksAck(t *testing.T) {
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	var acked atomic.Bool
	server := reloadTestServer(t, dir, &acked)
	defer server.Close()

	// NewPoller directly: newTestPoller would replace signalFunc with a
	// no-op, and this test needs the real command-backed reloader.
	p := newReloadCommandPoller(t, server.URL, dir, scriptFailNoisily)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if acked.Load() {
		t.Error("config must NOT be acked when nebula_reload_command fails")
	}
}

// TestPoller_ReloadCommandTimeout_BlocksAck: a hook that hangs (and leaves a
// child behind) must not be mistaken for a delivered reload either.
func TestPoller_ReloadCommandTimeout_BlocksAck(t *testing.T) {
	shrinkReloadTimeout(t, 100*time.Millisecond, 200*time.Millisecond)

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	var acked atomic.Bool
	server := reloadTestServer(t, dir, &acked)
	defer server.Close()

	p := newReloadCommandPoller(t, server.URL, dir, scriptSleepLong)

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if acked.Load() {
		t.Error("config must NOT be acked when nebula_reload_command times out")
	}
}

// TestPoller_ReloadCommandSuccess_Acks: the happy path — the command runs,
// the config is acknowledged. It polls for the ack instead of racing a fixed
// wall-clock window, so a loaded CI runner cannot turn a delivered reload
// into a spurious failure (see issue #346).
func TestPoller_ReloadCommandSuccess_Acks(t *testing.T) {
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	var acked atomic.Bool
	server := reloadTestServer(t, dir, &acked)
	defer server.Close()

	p := newReloadCommandPoller(t, server.URL, dir, scriptSucceed)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()

	waitForAck(t, &acked, 10*time.Second)
	cancel()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("Run did not return after the ack within %v", 15*time.Second)
	}
}

// TestReenrollReload_Selection: re-enroll uses the same precedence — the
// command (when set) wins over the pid-file SIGHUP seam; with neither, no
// reload hook is installed.
func TestReenrollReload_Selection(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	var signaledPID string
	seam := func(pidFile string) error { signaledPID = pidFile; return nil }

	reload := reenrollReload(context.Background(), ReenrollOptions{ReloadCommand: scriptTouch(marker), PIDFile: "/run/nebula.pid"}, seam)
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

	reload = reenrollReload(context.Background(), ReenrollOptions{PIDFile: "/run/nebula.pid"}, seam)
	if err := reload(); err != nil {
		t.Fatal(err)
	}
	if signaledPID != "/run/nebula.pid" {
		t.Errorf("signaled pid file = %q, want /run/nebula.pid", signaledPID)
	}

	if reload = reenrollReload(context.Background(), ReenrollOptions{}, seam); reload != nil {
		t.Error("no command and no pid file should install no reload hook")
	}
}
