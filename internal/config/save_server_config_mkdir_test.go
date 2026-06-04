package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSaveServerConfig_CreatesParentDir pins #215: SaveServerConfig must create
// the parent directory before writing the temp file, so `nebula-mgmt init`
// into a config path under a not-yet-existing directory succeeds (the agent
// path already does this via SaveAgentConfig).
func TestSaveServerConfig_CreatesParentDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc", "nebula-mgmt")
	path := filepath.Join(dir, "server.yml")

	if err := SaveServerConfig(path, &ServerConfig{}); err != nil {
		t.Fatalf("SaveServerConfig into non-existent dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config not written: %v", err)
	}
}
