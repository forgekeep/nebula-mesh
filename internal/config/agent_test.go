package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAgentConfig_ValidFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	data := []byte(`server_url: "https://mgmt.example.com:8080"
data_dir: "/etc/nebula"
poll_interval: "60s"
nebula_config_path: "/etc/nebula/config.yml"
nebula_pid_file: "/run/nebula.pid"
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ServerURL != "https://mgmt.example.com:8080" {
		t.Errorf("ServerURL = %q, want %q", cfg.ServerURL, "https://mgmt.example.com:8080")
	}
	if cfg.DataDir != "/etc/nebula" {
		t.Errorf("DataDir = %q, want %q", cfg.DataDir, "/etc/nebula")
	}
	if cfg.PollInterval != 60*time.Second {
		t.Errorf("PollInterval = %v, want %v", cfg.PollInterval, 60*time.Second)
	}
	if cfg.NebulaConfigPath != "/etc/nebula/config.yml" {
		t.Errorf("NebulaConfigPath = %q, want %q", cfg.NebulaConfigPath, "/etc/nebula/config.yml")
	}
	if cfg.NebulaPIDFile != "/run/nebula.pid" {
		t.Errorf("NebulaPIDFile = %q, want %q", cfg.NebulaPIDFile, "/run/nebula.pid")
	}
}

func TestLoadAgentConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	data := []byte(`server_url: "https://mgmt.example.com"
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.DataDir != "/etc/nebula" {
		t.Errorf("DataDir = %q, want default %q", cfg.DataDir, "/etc/nebula")
	}
	if cfg.PollInterval != 30*time.Second {
		t.Errorf("PollInterval = %v, want default %v", cfg.PollInterval, 30*time.Second)
	}
	if cfg.NebulaConfigPath != "/etc/nebula/config.yml" {
		t.Errorf("NebulaConfigPath = %q, want default %q", cfg.NebulaConfigPath, "/etc/nebula/config.yml")
	}
}

func TestLoadAgentConfig_MissingServerURL(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	data := []byte("{}\n")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadAgentConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for missing server_url, got nil")
	}
}

func TestLoadAgentConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	data := []byte("{{invalid yaml")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadAgentConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}
