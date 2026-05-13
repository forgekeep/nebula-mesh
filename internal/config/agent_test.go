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

func TestSaveAgentConfig_AtomicWriteAndMode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sub", "agent.yml")

	cfg := DefaultAgentConfig()
	cfg.ServerURL = "https://mgmt.example.com:8080"
	cfg.PollInterval = 45 * time.Second
	cfg.NebulaPIDFile = "/run/nebula.pid"

	if err := SaveAgentConfig(cfgPath, cfg); err != nil {
		t.Fatalf("SaveAgentConfig: %v", err)
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat saved config: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("config mode = %v, want 0600", mode)
	}

	loaded, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	if loaded.ServerURL != cfg.ServerURL {
		t.Errorf("ServerURL = %q, want %q", loaded.ServerURL, cfg.ServerURL)
	}
	if loaded.PollInterval != cfg.PollInterval {
		t.Errorf("PollInterval = %v, want %v", loaded.PollInterval, cfg.PollInterval)
	}
	if loaded.NebulaPIDFile != cfg.NebulaPIDFile {
		t.Errorf("NebulaPIDFile = %q, want %q", loaded.NebulaPIDFile, cfg.NebulaPIDFile)
	}

	entries, err := os.ReadDir(filepath.Dir(cfgPath))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "agent.yml" {
			t.Errorf("leftover file in config dir: %s", e.Name())
		}
	}
}

func TestSaveAgentConfig_Overwrite(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	cfg := DefaultAgentConfig()
	cfg.ServerURL = "https://first.example.com"
	if err := SaveAgentConfig(cfgPath, cfg); err != nil {
		t.Fatalf("first save: %v", err)
	}

	cfg.ServerURL = "https://second.example.com"
	if err := SaveAgentConfig(cfgPath, cfg); err != nil {
		t.Fatalf("second save: %v", err)
	}

	loaded, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	if loaded.ServerURL != "https://second.example.com" {
		t.Errorf("ServerURL = %q, want second", loaded.ServerURL)
	}
}

func TestSaveAgentConfig_RejectsEmpty(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "agent.yml")
	if err := SaveAgentConfig(cfgPath, nil); err == nil {
		t.Fatal("expected error for nil cfg")
	}
	if err := SaveAgentConfig(cfgPath, &AgentConfig{}); err == nil {
		t.Fatal("expected error for missing server_url")
	}
}
