//go:build !windows

package agent

import "strconv"

// Shell snippets for the reload tests, in the dialect of the interpreter
// reloadShellCommand picks on this platform. The Windows file defines the
// same names in cmd.exe syntax so the tests themselves stay OS-agnostic.
const (
	scriptSucceed     = "true"
	scriptFailNoisily = "echo boom-detail >&2; exit 3"
	scriptSleepLong   = "sleep 60"

	// scriptFlood prints 64 KiB and fails, to exercise the output cap.
	// Pure POSIX shell doubling — no coreutils dependency.
	scriptFlood = "s=xxxxxxxxxxxxxxxx; i=0; " +
		"while [ $i -lt 12 ]; do s=\"$s$s\"; i=$((i+1)); done; " +
		"echo \"$s\"; exit 3"
)

func scriptTouch(path string) string { return "touch " + strconv.Quote(path) }

// scriptTouchThenSleep signals that the hook has really started, then hangs.
func scriptTouchThenSleep(path string) string { return scriptTouch(path) + "; " + scriptSleepLong }
