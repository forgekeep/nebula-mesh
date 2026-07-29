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

func TestLoadServerConfig_TrustedProxyCIDRs(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")
	data := []byte(`rate_limit:
  trust_proxy_header: true
  trusted_proxies:
    - "10.42.0.0/16"
    - "2001:db8::/32"
`)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	prefixes, err := cfg.RateLimit.TrustedProxyPrefixes()
	if err != nil {
		t.Fatalf("TrustedProxyPrefixes: %v", err)
	}
	if len(prefixes) != 2 || prefixes[0].String() != "10.42.0.0/16" || prefixes[1].String() != "2001:db8::/32" {
		t.Fatalf("prefixes = %v", prefixes)
	}
}

func TestLoadServerConfig_RejectsInvalidTrustedProxyCIDR(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")
	data := []byte(`rate_limit:
  trust_proxy_header: true
  trusted_proxies: ["not-a-cidr"]
`)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadServerConfig(cfgPath); err == nil {
		t.Fatal("LoadServerConfig accepted invalid trusted proxy CIDR")
	}
}

func TestLoadServerConfig_CAImportSecuritySettings(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")
	data := []byte(`listen: "127.0.0.1:8080"
trusted_secret_ingress_proxy: true
ca_import:
  max_argon2_memory_kib: 131072
  max_argon2_iterations: 3
  max_argon2_parallelism: 2
`)
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TrustedSecretIngressProxy {
		t.Fatal("TrustedSecretIngressProxy = false, want true")
	}
	if cfg.CAImport.MaxArgon2MemoryKiB != 131072 || cfg.CAImport.MaxArgon2Iterations != 3 || cfg.CAImport.MaxArgon2Parallelism != 2 {
		t.Fatalf("CAImport = %+v", cfg.CAImport)
	}
}

func TestMetricsConfig_RequireAuthEnabled(t *testing.T) {
	// Default (omitted) gates /metrics behind bearer auth (#262): the metric
	// labels expose host/network/CA IDs, so unauthenticated scraping is now
	// opt-in.
	var m MetricsConfig
	if !m.RequireAuthEnabled() {
		t.Error("RequireAuthEnabled() = false for unset config, want true (auth-gated by default)")
	}

	// Operators on a trusted network opt out explicitly.
	f := false
	m.RequireAuth = &f
	if m.RequireAuthEnabled() {
		t.Error("RequireAuthEnabled() = true with require_auth: false, want false")
	}

	tr := true
	m.RequireAuth = &tr
	if !m.RequireAuthEnabled() {
		t.Error("RequireAuthEnabled() = false with require_auth: true, want true")
	}
}

func TestLoadServerConfig_MetricsRequireAuthDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Metrics.RequireAuthEnabled() {
		t.Error("metrics.require_auth default = false, want true (#262)")
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
	if loaded.Listen != original.Listen {
		t.Errorf("roundtrip mismatch: Listen loaded=%q want=%q", loaded.Listen, original.Listen)
	}
}

func TestSaveServerConfig_AtomicReplace(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	if err := os.WriteFile(cfgPath, []byte("listen: \":7000\"\nlog_level: \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	updated := &ServerConfig{Listen: ":8000", DataDir: "/d", DBPath: "/d/db", LogLevel: "info"}
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
		{"threshold=0", 0, false},      // 0 = unset, OK, will apply default
		{"threshold=-0.1", -0.1, true}, // negative, not allowed
		{"threshold=1.0", 1.0, true},   // >= 1.0, not allowed
		{"threshold=1.5", 1.5, true},   // > 1.0, not allowed
		{"threshold=0.5", 0.5, false},  // valid
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

// TestLoadServerConfig_DetectsLegacyAPIKey verifies that the detection of
// legacy `api_key:` in YAML works for top-level keys.
func TestLoadServerConfig_DetectsLegacyAPIKey(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`listen: ":8080"
data_dir: "/tmp"
db_path: "/tmp/test.db"
api_key: "legacy-key"
log_level: "info"
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !cfg.HasLegacyAPIKey() {
		t.Errorf("HasLegacyAPIKey() = false, want true (api_key: field present)")
	}
}

// TestLoadServerConfig_NoFalsePositive_Nested verifies that nested api_key
// values (under other keys) do not trigger the legacy detection.
func TestLoadServerConfig_NoFalsePositive_Nested(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`listen: ":8080"
data_dir: "/tmp"
db_path: "/tmp/test.db"
metrics:
  api_key: "nested-should-not-trigger"
log_level: "info"
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.HasLegacyAPIKey() {
		t.Errorf("HasLegacyAPIKey() = true, want false (nested api_key: should not trigger)")
	}
}

// TestLoadServerConfig_NoFalsePositive_Commented verifies that commented-out
// api_key: does not trigger the legacy detection.
func TestLoadServerConfig_NoFalsePositive_Commented(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`listen: ":8080"
data_dir: "/tmp"
db_path: "/tmp/test.db"
# api_key: "should-not-trigger"
log_level: "info"
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.HasLegacyAPIKey() {
		t.Errorf("HasLegacyAPIKey() = true, want false (commented api_key: should not trigger)")
	}
}

// TestLoadServerConfig_NoFalsePositive_StringValue verifies that api_key
// mentioned within string values does not trigger the legacy detection.
func TestLoadServerConfig_NoFalsePositive_StringValue(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "server.yml")

	data := []byte(`listen: ":8080"
data_dir: "/tmp"
db_path: "/tmp/test.db"
note: "api_key: should not trigger"
log_level: "info"
`)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.HasLegacyAPIKey() {
		t.Errorf("HasLegacyAPIKey() = true, want false (api_key: in string value should not trigger)")
	}
}
