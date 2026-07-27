package agent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// reloadCommandTimeout bounds a nebula_reload_command run. A hook that
// hangs would otherwise stall the poll loop forever; var (not const) so
// tests can shrink it.
var reloadCommandTimeout = 30 * time.Second

// reloadCommandWaitDelay is how long we keep draining output after the
// command's process group has been terminated. Terminating the group is
// best-effort — a descendant can be stopped, uninterruptible, or in another
// group entirely — and any survivor still holds the inherited output pipe.
// Without this bound cmd.Wait blocks on that pipe for as long as the
// survivor lives, defeating the timeout it was meant to enforce. var (not
// const) so tests can shrink it.
var reloadCommandWaitDelay = 2 * time.Second

// reloadCommandOutputLimit caps the combined output retained for the error
// message. A chatty (or runaway) hook writes for as long as it likes, so an
// unbounded buffer is unbounded agent memory. 8 KiB is far more than a
// service manager prints on failure and still fits a log line's worth of
// context.
const reloadCommandOutputLimit = 8 << 10

// nebulaReloader returns the reload hook for the given agent settings:
// when reloadCommand is set it is run through the system shell (taking
// precedence over the PID file), otherwise the classic SIGHUP to the PID
// named in pidFile. A failing or timed-out command surfaces its combined
// output in the error so the poller's no-ack retry loop logs something
// actionable.
// The returned hook takes the caller's context so that shutting the agent
// down does not have to wait out a hook that is wedged: canceling it
// terminates the command's process group the same way the timeout does.
// SIGHUP delivery ignores the context — it is a single syscall.
func nebulaReloader(reloadCommand, pidFile string) func(context.Context) error {
	if reloadCommand == "" {
		return func(context.Context) error { return signalNebulaFromPID(pidFile) }
	}
	return func(ctx context.Context) error { return runReloadCommand(ctx, reloadCommand) }
}

// runReloadCommand executes one reload hook, bounded by both the caller's
// context and the reload timeout. The command runs in its own process group
// so either bound can take down everything it spawned rather than just the
// shell (see terminateReloadCommand).
func runReloadCommand(parent context.Context, reloadCommand string) error {
	ctx, cancel := context.WithTimeout(parent, reloadCommandTimeout)
	defer cancel()

	cmd := reloadShellCommand(ctx, reloadCommand)
	out := &cappedBuffer{limit: reloadCommandOutputLimit}
	// Same writer for both streams: os/exec then shares a single pipe and
	// copier, so stdout and stderr stay interleaved as CombinedOutput had them.
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Cancel = func() error { return terminateReloadCommand(cmd) }
	cmd.WaitDelay = reloadCommandWaitDelay

	err := cmd.Run()
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("nebula_reload_command timed out after %s (process group terminated): %s",
			reloadCommandTimeout, out.String())
	case errors.Is(ctx.Err(), context.Canceled):
		// The agent is shutting down. Whether the reload landed is
		// unknowable, so this stays an error and the config ack is
		// suppressed — the next start re-applies and retries.
		return fmt.Errorf("nebula_reload_command interrupted by shutdown (process group terminated): %s",
			out.String())
	case err == nil:
		return nil
	case errors.Is(err, exec.ErrWaitDelay):
		// The hook itself exited 0; only its output pipe outlived it,
		// because something it spawned still holds the write end. The
		// reload was delivered, so let the config ack through — we have
		// already stopped reading, so nothing leaks on our side.
		return nil
	default:
		return fmt.Errorf("nebula_reload_command failed: %w: %s", err, out.String())
	}
}

// cappedBuffer accumulates at most limit bytes and counts the rest. Writes
// past the cap are discarded rather than rejected: returning an error would
// make os/exec close the pipe and hand the hook an EPIPE/SIGPIPE it never
// asked for.
//
// The mutex guards against os/exec's copier goroutine still running when
// Wait returns early on WaitDelay.
type cappedBuffer struct {
	limit int

	mu      sync.Mutex
	buf     []byte
	dropped int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	total := len(p)
	if room := b.limit - len(b.buf); room > 0 {
		kept := min(room, len(p))
		b.buf = append(b.buf, p[:kept]...)
		p = p[kept:]
	}
	b.dropped += len(p)
	return total, nil
}

// String renders the captured output, noting how much was dropped so an
// operator reading the log knows the message is not the whole story.
func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.dropped == 0 {
		return string(b.buf)
	}
	return fmt.Sprintf("%s… [%d more bytes truncated]", b.buf, b.dropped)
}
