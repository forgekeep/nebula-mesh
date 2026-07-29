package main

import (
	"strings"
	"testing"
)

func TestRunCAImport_IsWired(t *testing.T) {
	err := runCA([]string{
		"import",
		"--server", "http://mesh.example.com",
		"--api-key", "api-key",
		"--name", "existing",
		"--cert-file", "/missing/ca.crt",
		"--key-file", "/missing/ca.key",
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS or literal-loopback HTTP") {
		t.Fatalf("runCA(import) error = %v", err)
	}
}

// TestRun_UnknownCommand_Errors pins the top-level dispatch: an unrecognized
// command must be a usage error, never a silent no-op.
func TestRun_UnknownCommand_Errors(t *testing.T) {
	if err := runHost([]string{"crate", "--name", "x"}); err == nil ||
		!strings.Contains(err.Error(), "unknown host subcommand") {
		t.Errorf("runHost(crate) error = %v, want unknown-subcommand error", err)
	}
	if err := runCA([]string{"rotat"}); err == nil ||
		!strings.Contains(err.Error(), "unknown ca subcommand") {
		t.Errorf("runCA(rotat) error = %v, want unknown-subcommand error", err)
	}
}

// TestRejectsStrayPositionalArgs — Go's flag parser stops at the first
// non-flag token, so a stray operand silently drops every flag after it.
// `host create extra --name x` used to run with no name at all; it must be a
// usage error instead.
func TestRejectsStrayPositionalArgs(t *testing.T) {
	cases := []struct {
		name string
		call func() error
	}{
		{"host create", func() error {
			return runHost([]string{"create", "extra", "--name", "x", "--api-key", "k", "--ip", "10.0.0.1", "--network", "n"})
		}},
		{"host list", func() error { return runHost([]string{"list", "extra", "--api-key", "k"}) }},
		{"network create", func() error {
			return runNetwork([]string{"create", "extra", "--name", "n", "--cidr", "10.0.0.0/24", "--api-key", "k"})
		}},
		{"user create", func() error { return runUser([]string{"create", "extra", "--api-key", "k"}) }},
		{"apikey create", func() error {
			return runAPIKey([]string{"create", "extra", "--api-key", "k", "--operator", "o"})
		}},
		{"ops mint-admin-key", func() error { return runOps([]string{"mint-admin-key", "extra", "--config", "c"}) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if err == nil || !strings.Contains(err.Error(), "unexpected argument") {
				t.Errorf("error = %v, want the stray operand rejected", err)
			}
		})
	}
}

// TestCARotate_RequiresExactlyOneOperand — `ca rotate` is the one command
// with a positional operand. A second one means a flag was swallowed, which
// would otherwise rotate whichever CA happened to be parsed first.
func TestCARotate_RequiresExactlyOneOperand(t *testing.T) {
	if err := runCA([]string{"rotate", "--api-key", "k", "ca-1", "ca-2"}); err == nil ||
		!strings.Contains(err.Error(), "usage:") {
		t.Errorf("two operands: error = %v, want usage error", err)
	}
	if err := runCA([]string{"rotate", "--api-key", "k"}); err == nil ||
		!strings.Contains(err.Error(), "usage:") {
		t.Errorf("no operand: error = %v, want usage error", err)
	}
}
