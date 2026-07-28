//go:build windows

package agent

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
)

// reloadShellCommand builds the cmd.exe invocation for a reload hook.
//
// The command line is handed over verbatim through SysProcAttr.CmdLine
// rather than assembled from Args. os/exec would quote the hook with
// syscall.EscapeArg, whose backslash-escaped quotes cmd.exe does not
// understand — an operator command containing quotes or redirections would
// arrive mangled. Passing the raw line gives `cmd /C <command>` the exact
// text from agent.yml, which is what the documented contract promises. The
// leading token is cmd.exe's own argv[0]; the interpreter it actually runs
// is the resolved path below.
//
// CREATE_NEW_PROCESS_GROUP mirrors the Unix Setpgid: it keeps console
// signals aimed at an interactively-run agent from reaching the hook.
func reloadShellCommand(ctx context.Context, command string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, commandInterpreter()) // #nosec G204 -- resolved from COMSPEC/System32, never a bare PATH lookup
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine:       "cmd /C " + command,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	return cmd
}

// terminateReloadCommand kills the reload command and everything it spawned.
// Windows has no killpg: TerminateProcess on cmd.exe leaves the process it
// launched — the actual service-manager call — running and holding the
// inherited output pipe, so walk the tree with taskkill /T instead.
func terminateReloadCommand(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	kill := exec.Command(system32("taskkill.exe"), // #nosec G204 -- fixed system binary; the only variable is our own child's pid
		"/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
	if err := kill.Run(); err != nil {
		// taskkill missing or the tree already gone — still make sure the
		// interpreter itself is not left behind.
		return cmd.Process.Kill()
	}
	return nil
}

// commandInterpreter resolves cmd.exe from System32.
//
// Deliberately not a PATH lookup and deliberately not COMSPEC: the agent
// runs as LocalSystem, so an environment or PATH entry writable by a lesser
// user would be a privilege-escalation path. COMSPEC is also a correctness
// hazard here — the command line we build is cmd.exe syntax (`/C`), so
// honouring a COMSPEC that points at some other interpreter would hand it
// flags it does not understand.
func commandInterpreter() string {
	return system32("cmd.exe")
}

func system32(name string) string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", name)
}
