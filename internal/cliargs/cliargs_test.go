package cliargs

import (
	"flag"
	"io"
	"strings"
	"testing"
)

func parsed(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("name", "", "name")
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse(%v): %v", args, err)
	}
	return fs
}

func TestRejectPositional(t *testing.T) {
	guard := New("run `x help` for usage")

	if err := guard.RejectPositional(parsed(t, "--name", "ok")); err != nil {
		t.Errorf("clean flag set rejected: %v", err)
	}

	// Go stops parsing at "stray", so --name never reaches the flag set.
	fs := parsed(t, "stray", "--name", "dropped")
	if fs.Lookup("name").Value.String() != "" {
		t.Fatal("precondition: expected the flag after the operand to be dropped")
	}
	err := guard.RejectPositional(fs)
	if err == nil {
		t.Fatal("stray operand accepted")
	}
	if strings.Contains(err.Error(), "stray") {
		t.Errorf("error = %v, must not copy the operand", err)
	}
	if !strings.Contains(err.Error(), "unexpected argument after flags; flags that follow it were ignored") {
		t.Errorf("error = %v, want the positional-argument category and ignored-flags explanation", err)
	}
	if !strings.Contains(err.Error(), "run `x help` for usage") {
		t.Errorf("error = %v, want the usage hint appended", err)
	}
}

func TestGuardWithoutHint(t *testing.T) {
	err := Guard{}.UnknownCommand("command")
	if err == nil || strings.HasSuffix(err.Error(), "; ") {
		t.Fatalf("error = %v, want no dangling hint separator", err)
	}
	if !strings.Contains(err.Error(), "unknown command") || strings.Contains(err.Error(), "bogus") {
		t.Errorf("error = %v", err)
	}
}

// TestUnclassifiedArgumentsAreNeverEchoed — SEC-DIAGNOSTIC-001: command words
// and positional operands are unclassified input, so diagnostics must not rely
// on recognizer-based redaction before deciding whether to copy them.
func TestUnclassifiedArgumentsAreNeverEchoed(t *testing.T) {
	values := []string{
		"correct-horse-battery-staple",
		"test-api-key-ThisIsNotReal",
		"legacy-enrollment-token-ThisIsNotReal",
		"nme_ThisIsNotARealTokenJustTestData",
		"nmi_ThisIsNotARealTokenJustTestData",
	}
	guard := New("hint")
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			if err := guard.UnknownCommand("command"); strings.Contains(err.Error(), value) {
				t.Errorf("unknown-command error leaked unclassified input: %v", err)
			}
			if err := guard.RejectPositional(parsed(t, value)); strings.Contains(err.Error(), value) {
				t.Errorf("positional-argument error leaked unclassified input: %v", err)
			}
		})
	}
}
