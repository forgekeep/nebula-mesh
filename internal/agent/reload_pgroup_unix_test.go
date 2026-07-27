//go:build !windows

package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestNebulaReloader_TimeoutKillsProcessTree is the regression test for a
// reload hook that outlives its shell.
//
// `sh -c` forks for a background job, a pipeline, or any service manager
// that spawns a helper, and those children inherit the command's
// stdout/stderr. Killing only the shell left them running, which broke the
// timeout twice over: the write end of the output pipe stayed open so the
// agent blocked in Wait for the child's whole lifetime, and the work the
// operator asked to abort carried on regardless.
//
// The two assertions below cover the two halves separately — WaitDelay
// bounds how long the agent waits, terminating the process group is what
// actually stops the child — so neither fix can silently regress behind the
// other.
func TestNebulaReloader_TimeoutKillsProcessTree(t *testing.T) {
	const (
		childWork  = 2 * time.Second
		reapMargin = 500 * time.Millisecond
	)
	shrinkReloadTimeout(t, 200*time.Millisecond, 500*time.Millisecond)

	dir := t.TempDir()
	marker := filepath.Join(dir, "child-finished")
	// A backgrounded grandchild that inherits the pipe and outlives `sh`.
	// It only touches the marker once its work completes, so the marker is
	// the proof that killing the group really stopped it.
	script := fmt.Sprintf("(sleep %d; touch %s) & wait",
		int(childWork.Seconds()), strconv.Quote(marker))

	start := time.Now()
	err := nebulaReloader(script, "")(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err = %v, want a timeout error", err)
	}
	// Half the child's runtime: comfortably above timeout+WaitDelay, and
	// unambiguously below "blocked until the child exited".
	if budget := childWork / 2; elapsed > budget {
		t.Errorf("reload returned after %v, want under %v — a surviving child still blocks the poll loop",
			elapsed, budget)
	}

	time.Sleep(time.Until(start.Add(childWork + reapMargin)))
	if _, err := os.Stat(marker); err == nil {
		t.Error("the backgrounded child ran to completion — the process group was not terminated")
	} else if !os.IsNotExist(err) {
		t.Errorf("stat marker: %v", err)
	}
}
