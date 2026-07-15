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
	if cfg.SigningKeyPath != "/etc/nebula-agent/host.signing.key" {
		t.Errorf("SigningKeyPath = %q, want default %q", cfg.SigningKeyPath, "/etc/nebula-agent/host.signing.key")
	}
}

// TestAgentConfig_DefaultsHaveSigningKeyPath pins the per-agent signing-key
// path to /etc/nebula-agent/ — outside Nebula's data_dir. The location is part
// of the supported on-disk layout (ADR 0004 + #88) and is documented in
// docs/agent.md; changing it requires a migration plan.
func TestAgentConfig_DefaultsHaveSigningKeyPath(t *testing.T) {
	cfg := DefaultAgentConfig()
	if cfg.SigningKeyPath != "/etc/nebula-agent/host.signing.key" {
		t.Errorf("SigningKeyPath = %q, want %q", cfg.SigningKeyPath, "/etc/nebula-agent/host.signing.key")
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

func TestAgentConfigImportProfileRoundTripAndLegacyDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yml")
	cfg := DefaultAgentConfig()
	cfg.ServerURL = "https://mesh.example.test"
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.NebulaConfigPath = "/custom/nebula/node.yml"
	cfg.NebulaCAPath = "/custom/pki/root.pem"
	cfg.NebulaCertPath = "/custom/pki/node.pem"
	cfg.NebulaKeyPath = "/custom/pki/node.key"
	cfg.ImportSessionID = "import-session"
	if err := SaveAgentConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadAgentConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ResolvedNebulaCAPath() != cfg.NebulaCAPath || loaded.ResolvedNebulaCertPath() != cfg.NebulaCertPath ||
		loaded.ResolvedNebulaKeyPath() != cfg.NebulaKeyPath || loaded.ImportSessionID != cfg.ImportSessionID {
		t.Fatalf("round-trip profile = %#v", loaded)
	}

	legacy := &AgentConfig{DataDir: "/legacy/nebula"}
	if legacy.ResolvedNebulaCAPath() != "/legacy/nebula/ca.crt" ||
		legacy.ResolvedNebulaCertPath() != "/legacy/nebula/host.crt" ||
		legacy.ResolvedNebulaKeyPath() != "/legacy/nebula/host.key" {
		t.Fatalf("legacy resolved paths: ca=%q cert=%q key=%q", legacy.ResolvedNebulaCAPath(), legacy.ResolvedNebulaCertPath(), legacy.ResolvedNebulaKeyPath())
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

func TestValidateAgentServerURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		allowInsecure bool
		wantErr       bool
	}{
		{name: "https accepted", url: "https://mgmt.example.com:8080"},
		{name: "http non-loopback refused", url: "http://mgmt.example.com:8080", wantErr: true},
		{name: "http private-range still refused", url: "http://10.0.0.5:8080", wantErr: true},
		{name: "http localhost allowed", url: "http://localhost:8080"},
		{name: "http 127.0.0.1 allowed", url: "http://127.0.0.1:8080"},
		{name: "http [::1] allowed", url: "http://[::1]:8080"},
		{name: "http non-loopback with opt-out", url: "http://mgmt.example.com:8080", allowInsecure: true},
		{name: "non-http scheme refused", url: "file:///etc/passwd", wantErr: true},
		{name: "missing host refused", url: "https://", wantErr: true},
		{name: "empty refused", url: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAgentServerURL(tc.url, tc.allowInsecure)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateAgentServerURL(%q, allowInsecure=%v) error = %v, wantErr %v", tc.url, tc.allowInsecure, err, tc.wantErr)
			}
		})
	}
}

// TestLoadAgentConfig_PlaintextHTTPRefused pins the load-time guard: an
// on-disk config pointing at a cleartext non-loopback URL fails to load
// unless allow_insecure_http is set.
func TestLoadAgentConfig_PlaintextHTTPRefused(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	data := []byte("server_url: \"http://mgmt.example.com:8080\"\n")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAgentConfig(cfgPath); err == nil {
		t.Fatal("expected error for plaintext non-loopback server_url, got nil")
	}

	data = []byte("server_url: \"http://mgmt.example.com:8080\"\nallow_insecure_http: true\n")
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("opt-out config refused: %v", err)
	}
	if !cfg.AllowInsecureHTTP {
		t.Error("AllowInsecureHTTP not loaded from YAML")
	}
}
