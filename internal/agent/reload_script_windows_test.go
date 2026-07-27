//go:build windows

package agent

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
