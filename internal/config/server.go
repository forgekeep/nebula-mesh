package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

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

	// MasterKey is a base64-encoded 32-byte AES-256 key used to wrap
	// per-CA DEKs in the cas table. May be supplied via the
	// NEBULA_MGMT_MASTER_KEY env var instead.
	MasterKey string `yaml:"master_key,omitempty"`

	// AllowSelfRegistration controls whether unauthenticated visitors can
	// create their own operator account through /ui/register. Defaults to
	// false so closed deployments stay closed by default; administrators
	// can still create operators manually via the existing
	// `nebula-mgmt user create` CLI or `POST /api/v1/operators` API.
	AllowSelfRegistration bool `yaml:"allow_self_registration,omitempty"`

	// Metrics configures the optional /metrics Prometheus exporter. Default
	// is "enabled" so out-of-the-box installs can be scraped immediately;
	// air-gapped deployments can set Prometheus=false to drop the route.
	Metrics MetricsConfig `yaml:"metrics,omitempty"`

	// Alerts configures the cert-expiry alerter (see issue #41). Disabled
	// by default — operators must opt in by setting Enabled=true.
	Alerts AlertsConfig `yaml:"alerts,omitempty"`

	// RateLimit configures the per-IP, per-route-group token-bucket
	// limiter that fronts the Web UI and API (see issue #52). Enabled
	// by default so login + enrolment endpoints are protected from
	// online brute-force out of the box.
	RateLimit RateLimitConfig `yaml:"rate_limit,omitempty"`

	// Password configures the password policy applied to every server-
	// side password-setting path (see issue #48). All knobs are
	// optional: unset values fall back to the production defaults
	// (10-char min, 3-of-4 classes, common-pw + username block on).
	Password PasswordConfig `yaml:"password,omitempty"`

	// EnforceTOTP toggles admin-enforced 2FA (issue #49). When set, the
	// value is written into the server_settings table on startup so it
	// stays in effect across restarts. A nil pointer (unset YAML) leaves
	// the DB value alone — the future Settings UI (#47) will edit the
	// same row at runtime.
	EnforceTOTP *bool `yaml:"enforce_2fa,omitempty"`
}

// PasswordConfig overrides the password policy defaults.
type PasswordConfig struct {
	MinLength      *int  `yaml:"min_length,omitempty"`
	RequireClasses *int  `yaml:"require_classes,omitempty"`
	BlockCommon    *bool `yaml:"block_common,omitempty"`
	BlockUsername  *bool `yaml:"block_username,omitempty"`
}

// RateLimitConfig drives the rate-limit middleware. Enabled defaults to
// true; turn it off in trusted-network deployments by setting
// `rate_limit: { enabled: false }`. Set `trust_proxy_header: true` when
// running behind a reverse proxy that adds X-Forwarded-For.
type RateLimitConfig struct {
	// Enabled is a pointer so an absent YAML block defaults to "true"
	// (issue #52 requires on-by-default) while still allowing a
	// `rate_limit: { enabled: false }` to disable it.
	Enabled          *bool                          `yaml:"enabled,omitempty"`
	TrustProxyHeader bool                           `yaml:"trust_proxy_header,omitempty"`
	Groups           map[string]RateLimitGroupConfig `yaml:"groups,omitempty"`
}

// RateLimitGroupConfig is the per-group rate/burst pair.
type RateLimitGroupConfig struct {
	Rate  float64 `yaml:"rate"`
	Burst int     `yaml:"burst"`
}

// IsEnabled returns whether the limiter should run. Default: true.
func (c RateLimitConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// AlertsConfig drives the periodic cert-expiry scanner and its sinks.
// Threshold and Interval are parsed as Go durations (e.g. "72h", "5m").
type AlertsConfig struct {
	Enabled           bool   `yaml:"enabled,omitempty"`
	Interval          string `yaml:"interval,omitempty"`
	Threshold         string `yaml:"threshold,omitempty"`
	WebhookURL        string `yaml:"webhook_url,omitempty"`
	WebhookHMACSecret string `yaml:"webhook_hmac_secret,omitempty"`
}

// IntervalDuration returns Interval as a time.Duration. Falls back to 5m
// when unset or unparseable, matching the documented default.
func (a AlertsConfig) IntervalDuration() time.Duration {
	if a.Interval == "" {
		return 5 * time.Minute
	}
	d, err := time.ParseDuration(a.Interval)
	if err != nil || d <= 0 {
		return 5 * time.Minute
	}
	return d
}

// ThresholdDuration returns Threshold as a time.Duration. Falls back to 72h
// (three days) when unset or unparseable, matching the documented default.
func (a AlertsConfig) ThresholdDuration() time.Duration {
	if a.Threshold == "" {
		return 72 * time.Hour
	}
	d, err := time.ParseDuration(a.Threshold)
	if err != nil || d <= 0 {
		return 72 * time.Hour
	}
	return d
}

// MetricsConfig toggles the Prometheus exporter. Legacy Go expvar stays on
// /debug/vars regardless.
type MetricsConfig struct {
	// Prometheus is a pointer so an unset value (yaml omitted) is treated
	// as the default (true). A user setting `prometheus: false` cleanly
	// disables the exporter.
	Prometheus *bool `yaml:"prometheus,omitempty"`
}

// PrometheusEnabled returns whether the Prometheus exporter should be served.
// Defaults to true when unset.
func (m MetricsConfig) PrometheusEnabled() bool {
	if m.Prometheus == nil {
		return true
	}
	return *m.Prometheus
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
