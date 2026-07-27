package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// waitForFile blocks until path exists, so a test can be sure the reload
// hook is genuinely running before it interferes with it.
func waitForFile(t *testing.T, path string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reload hook never created %s within %v", path, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestNebulaReloader_ContextCancelInterrupts: canceling the caller's context
// terminates the hook instead of letting it run out the full timeout.
//
// Deliberately does NOT shrink reloadCommandTimeout — the whole point is that
// cancellation does not have to wait for it. With the hook bound to
// context.Background() this test hangs for the full 30s and trips the guard.
func TestNebulaReloader_ContextCancelInterrupts(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	reload := nebulaReloader(scriptTouchThenSleep(marker), "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- reload(ctx) }()

	waitForFile(t, marker, 10*time.Second)
	start := time.Now()
	cancel()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("an interrupted reload must report an error so the config ack stays suppressed")
		}
		if !strings.Contains(err.Error(), "interrupted by shutdown") {
			t.Errorf("err = %v, want the shutdown-interrupted error", err)
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("reload took %v to unwind after cancel", elapsed)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("reload ignored its canceled context (timeout is %v)", reloadCommandTimeout)
	}
}

// TestPoller_ReloadCommandShutdown_DoesNotWaitOutTimeout: stopping the agent
// while a hook is wedged must not block for the reload timeout.
//
// This is the operator-visible half: with the hook on context.Background(),
// `systemctl stop nebula-agent` sits there for 30 seconds — long enough for a
// supervisor to escalate to SIGKILL on a stricter TimeoutStopSec.
func TestPoller_ReloadCommandShutdown_DoesNotWaitOutTimeout(t *testing.T) {
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	var acked atomic.Bool
	server := reloadTestServer(t, dir, &acked)
	defer server.Close()

	marker := filepath.Join(dir, "hook-started")
	p := newReloadCommandPoller(t, server.URL, dir, scriptTouchThenSleep(marker))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()

	waitForFile(t, marker, 10*time.Second)
	start := time.Now()
	cancel()

	select {
	case <-done:
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("shutdown took %v with a %v reload timeout", elapsed, reloadCommandTimeout)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Run did not return; shutdown is waiting out the %v reload timeout", reloadCommandTimeout)
	}
	if acked.Load() {
		t.Error("an interrupted reload must not be acked — delivery is unknown")
	}
}
