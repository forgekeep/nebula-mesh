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
