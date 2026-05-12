package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Listen     string      `yaml:"listen"`
	DataDir    string      `yaml:"data_dir"`
	DBPath     string      `yaml:"db_path"`
	APIKey     string      `yaml:"api_key"`
	UIPassword string      `yaml:"ui_password,omitempty"`
	LogLevel   string      `yaml:"log_level"`
	TLSCert    string      `yaml:"tls_cert,omitempty"`
	TLSKey     string      `yaml:"tls_key,omitempty"`
	OIDC       *OIDCConfig `yaml:"oidc,omitempty"`

	// AllowSelfRegistration controls whether unauthenticated visitors can
	// create their own operator account through /ui/register. Defaults to
	// false so closed deployments stay closed by default; administrators
	// can still create operators manually via the existing
	// `nebula-mgmt user create` CLI or `POST /api/v1/operators` API.
	AllowSelfRegistration bool `yaml:"allow_self_registration,omitempty"`
}

// OIDCConfig configures an OpenID Connect identity provider for operator
// login. If nil or Enabled=false, OIDC login is not offered.
type OIDCConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Issuer        string   `yaml:"issuer"`
	ClientID      string   `yaml:"client_id"`
	ClientSecret  string   `yaml:"client_secret"`
	RedirectURL   string   `yaml:"redirect_url"`
	Scopes        []string `yaml:"scopes,omitempty"`
	UsernameClaim string   `yaml:"username_claim,omitempty"` // default "preferred_username"
	NameClaim     string   `yaml:"name_claim,omitempty"`     // default "name"
	GroupsClaim   string   `yaml:"groups_claim,omitempty"`   // default "groups"
	AllowedGroups []string `yaml:"allowed_groups,omitempty"`
	AllowedEmails []string `yaml:"allowed_emails,omitempty"`
	DefaultRole   string   `yaml:"default_role,omitempty"` // default "admin"
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &ServerConfig{
		Listen:   ":8080",
		DataDir:  "/var/lib/nebula-mgmt",
		DBPath:   "/var/lib/nebula-mgmt/nebula.db",
		LogLevel: "info",
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return nil, fmt.Errorf("invalid log_level: %q (must be debug, info, warn, or error)", cfg.LogLevel)
	}

	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return nil, fmt.Errorf("tls_cert and tls_key must both be set or both empty")
	}

	return cfg, nil
}

// SaveServerConfig writes the config to path atomically (temp file + rename).
// Existing comments and unknown fields in the file are not preserved.
func SaveServerConfig(path string, cfg *ServerConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename temp config: %w", err)
	}
	return nil
}
