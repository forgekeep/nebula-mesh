// Package cliargs holds the argument-shape guards shared by the nebula-agent
// and nebula-mgmt entrypoints.
//
// Go's flag package stops parsing at the first non-flag token and leaves the
// rest as operands. A command line with a typo where a subcommand or flag
// belongs therefore runs with every later flag silently dropped —
// `nebula-agent enrool --server URL --token TOK` used to park in standby
// without ever contacting the server, which reads as a server-side failure.
// Both binaries reject that shape without copying the unclassified value into
// diagnostics.
package cliargs

import (
	"flag"
	"fmt"
)

// Guard reports argument-shape errors for a single binary. The zero value is
// usable; New attaches the per-binary usage hint appended to every message.
type Guard struct {
	helpHint string
}

// New returns a Guard whose errors end with helpHint (e.g. "run `nebula-agent
// help` for usage"). An empty hint is omitted.
func New(helpHint string) Guard {
	return Guard{helpHint: helpHint}
}

// RejectPositional fails when flag parsing left unconsumed operands. Commands
// that legitimately take an operand validate NArg themselves rather than
// calling this.
func (g Guard) RejectPositional(fs *flag.FlagSet) error {
	if fs.NArg() == 0 {
		return nil
	}
	return g.errorf("unexpected argument after flags; flags that follow it were ignored")
}

// UnknownCommand reports an unrecognized command word. kind names what was
// expected — "command", "host subcommand", "service action".
func (g Guard) UnknownCommand(kind string) error {
	return g.errorf("unknown %s", kind)
}

func (g Guard) errorf(format string, args ...any) error {
	message := fmt.Sprintf(format, args...)
	if g.helpHint == "" {
		return fmt.Errorf("%s", message)
	}
	return fmt.Errorf("%s; %s", message, g.helpHint)
}
