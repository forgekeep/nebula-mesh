package main

import (
	"strings"
	"testing"
)

func TestRunCAImportRequiresExplicitServer(t *testing.T) {
	err := runCAImport([]string{"--api-key", "test-key", "--name", "test-ca", "--cert-file", "/missing/ca.crt", "--key-file", "/missing/ca.key"})
	if err == nil || !strings.Contains(err.Error(), "--server is required") {
		t.Fatalf("ca import without --server = %v, want missing --server error", err)
	}
}
