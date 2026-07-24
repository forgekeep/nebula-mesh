package agent

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

// reloadCommandTimeout bounds a nebula_reload_command run. A hook that
// hangs would otherwise stall the poll loop forever; var (not const) so
// tests can shrink it.
var reloadCommandTimeout = 30 * time.Second

// nebulaReloader returns the reload hook for the given agent settings:
// when reloadCommand is set it is run through the system shell (taking
// precedence over the PID file), otherwise the classic SIGHUP to the PID
// named in pidFile. A failing or timed-out command surfaces its combined
// output in the error so the poller's no-ack retry loop logs something
// actionable.
func nebulaReloader(reloadCommand, pidFile string) func() error {
	if reloadCommand == "" {
		return func() error { return signalNebulaFromPID(pidFile) }
	}
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), reloadCommandTimeout)
		defer cancel()

		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.CommandContext(ctx, "cmd", "/C", reloadCommand) // #nosec G204 -- operator-controlled reload hook from agent config, documented API contract
		} else {
			cmd = exec.CommandContext(ctx, "sh", "-c", reloadCommand) // #nosec G204 -- operator-controlled reload hook from agent config, documented API contract
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("nebula_reload_command timed out after %s: %s", reloadCommandTimeout, out)
			}
			return fmt.Errorf("nebula_reload_command failed: %w: %s", err, out)
		}
		return nil
	}
}
