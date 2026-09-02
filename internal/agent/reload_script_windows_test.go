//go:build windows

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// Shell snippets for the reload tests, in cmd.exe syntax. The Unix file
// defines the same names for `sh -c`.
const (
	scriptSucceed     = "exit 0"
	scriptFailNoisily = "echo boom-detail 1>&2 & exit 3"
	// ping is the reliable cmd.exe sleep: `timeout /t` refuses to run when
	// stdin is redirected, which it always is under os/exec.
	scriptSleepLong = "ping -n 61 127.0.0.1 >nul"

	// scriptFlood prints ~60 KB and fails, to exercise the output cap.
	scriptFlood = "(for /L %i in (1,1,600) do @echo " +
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" +
		"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx) & exit 3"
)

// scriptTouch relies on the raw command line reaching cmd.exe unmangled:
// the temp path is quoted here and must survive as typed.
func scriptTouch(path string) string { return `type nul > "` + path + `"` }

// scriptTouchThenSleep signals that the hook has really started, then hangs.
func scriptTouchThenSleep(path string) string { return scriptTouch(path) + " & " + scriptSleepLong }

// writeReloadHookScript drops a hook under a directory whose name contains a
// space - the reason an operator quotes the path in the first place - and
// returns the script and the marker it writes.
//
// %~dp0 keeps the marker path out of the command line, so the line under test
// holds exactly the two quotes that wrap the script path and nothing else.
func writeReloadHookScript(t *testing.T) (script, marker string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "hook dir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	script = filepath.Join(dir, "hook.cmd")
	marker = filepath.Join(dir, "ran")
	if err := os.WriteFile(script, []byte("@echo off\r\ntype nul > \"%~dp0ran\"\r\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return script, marker
}
