//go:build !windows

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// reloadShellCommand builds the shell invocation for a reload hook and puts
// it in a fresh process group. Setpgid is what makes the timeout mean
// anything: `sh -c` frequently forks (background jobs, pipelines, a service
// manager that spawns helpers), and those children inherit the output pipe.
// Without a group to kill, terminating the shell leaves them running and
// holding that pipe open.
func reloadShellCommand(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "sh", "-c", command) // #nosec G204 -- operator-controlled reload hook from agent config, documented API contract
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

// terminateReloadCommand SIGKILLs the whole process group created above.
// The hook already had the full timeout to finish, so there is nothing left
// to be graceful about; a SIGTERM-then-wait dance would only extend the
// stall the timeout exists to prevent.
func terminateReloadCommand(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	// Negative PID addresses the group. The group id equals the shell's pid
	// because Setpgid made it a group leader.
	switch err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ESRCH):
		// Already gone. Reporting it as ErrProcessDone keeps os/exec from
		// turning a benign race into a spurious Wait error.
		return os.ErrProcessDone
	default:
		// No such group (Setpgid refused, or the shell was reaped between
		// the two calls) — at least take down the process itself.
		return cmd.Process.Kill()
	}
}
