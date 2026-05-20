package config

import (
	"fmt"
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

func TestLoadServerConfig_InvalidLogLevel(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`log_level: "dbug"`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadServerConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for invalid log_level, got nil")
	}
}

func TestLoadServerConfig_ValidLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "server.yml")

		data := []byte(`log_level: "` + level + `"`)
		if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
			t.Fatal(err)
		}

		cfg, err := LoadServerConfig(cfgPath)
		if err != nil {
			t.Fatalf("log_level=%q: unexpected error: %v", level, err)
		}
		if cfg.LogLevel != level {
			t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, level)
		}
	}
}

func TestLoadServerConfig_FileNotFound(t *testing.T) {
	_, err := LoadServerConfig("/nonexistent/path.yml")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadServerConfig_TLSPartialFails(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`tls_cert: "/etc/nebula/cert.pem"`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadServerConfig(cfgPath); err == nil {
		t.Fatal("expected error when only tls_cert is set, got nil")
	}
}

func TestSaveServerConfig_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	original := &ServerConfig{
		Listen:   ":9090",
		DataDir:  "/tmp/nebula",
		DBPath:   "/tmp/nebula/db",
		APIKey:   "abc123",
		LogLevel: "warn",
	}
	if err := SaveServerConfig(cfgPath, original); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat saved config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.APIKey != original.APIKey || loaded.Listen != original.Listen {
		t.Errorf("roundtrip mismatch: %+v vs %+v", loaded, original)
	}
}

func TestSaveServerConfig_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	if err := os.WriteFile(cfgPath, []byte("listen: \":7000\"\nlog_level: \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	updated := &ServerConfig{Listen: ":8000", DataDir: "/d", DBPath: "/d/db", APIKey: "k", LogLevel: "info"}
	if err := SaveServerConfig(cfgPath, updated); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Listen != ":8000" {
		t.Errorf("Listen = %q, want :8000", loaded.Listen)
	}
}

func TestLoadServerConfig_AcceptsCAAutoRotate(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`listen: ":8080"
data_dir: "/tmp"
db_path: "/tmp/test.db"
api_key: "test"
log_level: "info"
ca_auto_rotate:
  enabled: true
  interval: 6h
  threshold: 0.2
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.CAAutoRotate.Enabled {
		t.Errorf("CAAutoRotate.Enabled = %v, want true", cfg.CAAutoRotate.Enabled)
	}
	if cfg.CAAutoRotate.Threshold != 0.2 {
		t.Errorf("CAAutoRotate.Threshold = %v, want 0.2", cfg.CAAutoRotate.Threshold)
	}
}

func TestLoadServerConfig_RejectsCAAutoRotateBadThreshold(t *testing.T) {
	tests := []struct {
		name      string
		threshold float64
		wantErr   bool
	}{
		{"threshold=0", 0, false},          // 0 = unset, OK, will apply default
		{"threshold=-0.1", -0.1, true},     // negative, not allowed
		{"threshold=1.0", 1.0, true},       // >= 1.0, not allowed
		{"threshold=1.5", 1.5, true},       // > 1.0, not allowed
		{"threshold=0.5", 0.5, false},      // valid
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "server.yml")

			data := []byte(`listen: ":8080"
data_dir: "/tmp"
db_path: "/tmp/test.db"
api_key: "test"
log_level: "info"
ca_auto_rotate:
  enabled: true
  threshold: ` + fmt.Sprintf("%v", tt.threshold) + `
`)
			if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
				t.Fatal(err)
			}

			_, err := LoadServerConfig(cfgPath)
			if (err != nil) != tt.wantErr {
				t.Fatalf("threshold=%v: got error=%v, want error=%v", tt.threshold, err, tt.wantErr)
			}
		})
	}
}

func TestLoadServerConfig_RejectsCAAutoRotateBadInterval(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`listen: ":8080"
data_dir: "/tmp"
db_path: "/tmp/test.db"
api_key: "test"
log_level: "info"
ca_auto_rotate:
  enabled: true
  interval: 30s
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadServerConfig(cfgPath)
	if err == nil {
		t.Fatal("expected error for interval < 1m, got nil")
	}
}

// TestCookieSecureResolved covers GHSA-rqfj-vv8r-xhqc's resolution rules:
// explicit cookie_secure wins; otherwise the value is inferred from the
// presence of TLS material on the server.
func TestCookieSecureResolved(t *testing.T) {
	ptr := func(b bool) *bool { return &b }
	cases := []struct {
		name string
		cfg  ServerConfig
		want bool
	}{
		{"explicit_true", ServerConfig{CookieSecure: ptr(true)}, true},
		{"explicit_false_overrides_tls", ServerConfig{CookieSecure: ptr(false), TLSCert: "c", TLSKey: "k"}, false},
		{"unset_no_tls", ServerConfig{}, false},
		{"unset_with_tls", ServerConfig{TLSCert: "c", TLSKey: "k"}, true},
		{"unset_partial_tls_cert_only", ServerConfig{TLSCert: "c"}, false},
		{"unset_partial_tls_key_only", ServerConfig{TLSKey: "k"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.cfg.CookieSecureResolved(); got != c.want {
				t.Errorf("CookieSecureResolved() = %v, want %v", got, c.want)
			}
		})
	}
}
