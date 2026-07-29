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
	if !strings.Contains(err.Error(), `"stray"`) {
		t.Errorf("error = %v, want it to name the operand", err)
	}
	if !strings.Contains(err.Error(), "run `x help` for usage") {
		t.Errorf("error = %v, want the usage hint appended", err)
	}
}

func TestGuardWithoutHint(t *testing.T) {
	err := Guard{}.UnknownCommand("command", "bogus")
	if err == nil || strings.HasSuffix(err.Error(), "; ") {
		t.Fatalf("error = %v, want no dangling hint separator", err)
	}
	if !strings.Contains(err.Error(), `unknown command "bogus"`) {
		t.Errorf("error = %v", err)
	}
}

// TestRedactsBootstrapTokens — SEC-SECRET-001: a mistyped command line can put
// a bootstrap token where a command word belongs, and these errors land in
// logs, terminals and shell history. Both token purposes must be hidden while
// ordinary operands stay visible, or the message stops being actionable.
func TestRedactsBootstrapTokens(t *testing.T) {
	secrets := []string{
		"nme_ThisIsNotARealTokenJustTestData",
		"nmi_ThisIsNotARealTokenJustTestData",
	}
	for _, secret := range secrets {
		if got := Redact(secret); got != Redacted {
			t.Errorf("Redact(%q) = %q, want %q", secret, got, Redacted)
		}
		err := New("hint").UnknownCommand("command", secret)
		if strings.Contains(err.Error(), secret) {
			t.Errorf("token leaked into error: %v", err)
		}
		err = New("hint").RejectPositional(parsed(t, secret))
		if strings.Contains(err.Error(), secret) {
			t.Errorf("token leaked into operand error: %v", err)
		}
	}

	for _, harmless := range []string{"enrool", "host", "--name", "", "nme", "nmi"} {
		if got := Redact(harmless); got != harmless {
			t.Errorf("Redact(%q) = %q, want it unchanged", harmless, got)
		}
	}
}
