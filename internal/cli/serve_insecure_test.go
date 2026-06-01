package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestServe_RefusesPlaintextOnNonLoopback verifies the #179 guard fires at
// startup, before any DB/key work, when the config would serve cleartext on a
// routable address with no opt-out.
func TestServe_RefusesPlaintextOnNonLoopback(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")
	content := "listen: \"0.0.0.0:8080\"\n" +
		"data_dir: " + dir + "\n" +
		"db_path: " + filepath.Join(dir, "nebula.db") + "\n" +
		"log_level: info\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Serve(cfgPath, false)
	if err == nil {
		t.Fatal("Serve() = nil, want plaintext-refusal error")
	}
	if !strings.Contains(err.Error(), "plaintext HTTP") {
		t.Fatalf("Serve() err = %q, want a plaintext-HTTP refusal", err.Error())
	}
}
