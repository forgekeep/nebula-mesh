package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerConfig_ValidFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`listen: ":9090"
data_dir: "/tmp/nebula-mgmt"
db_path: "/tmp/nebula-mgmt/test.db"
api_key: "test-key-123"
log_level: "debug"
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen != ":9090" {
		t.Errorf("Listen = %q, want %q", cfg.Listen, ":9090")
	}
	if cfg.DataDir != "/tmp/nebula-mgmt" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/tmp/nebula-mgmt")
	}
	if cfg.DBPath != "/tmp/nebula-mgmt/test.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "/tmp/nebula-mgmt/test.db")
	}
	if cfg.APIKey != "test-key-123" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "test-key-123")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "debug")
	}
}

func TestLoadServerConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte("{}\n")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen != ":8080" {
		t.Errorf("Listen = %q, want default %q", cfg.Listen, ":8080")
	}
	if cfg.DataDir != "/var/lib/nebula-mgmt" {
		t.Errorf("DataDir = %q, want default %q", cfg.DataDir, "/var/lib/nebula-mgmt")
	}
	if cfg.DBPath != "/var/lib/nebula-mgmt/nebula.db" {
		t.Errorf("DBPath = %q, want default %q", cfg.DBPath, "/var/lib/nebula-mgmt/nebula.db")
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want default %q", cfg.LogLevel, "info")
	}
}

func TestLoadServerConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte("{{invalid yaml")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadServerConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadServerConfig_FileNotFound(t *testing.T) {
	_, err := LoadServerConfig("/nonexistent/path.yml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
