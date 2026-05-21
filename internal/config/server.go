package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// CAAutoRotateConfig configures the CA auto-rotation scanner: interval between scans,
// and threshold (as fraction of total lifetime) to trigger rotation.
// Defaults: Interval=6h, Threshold=0.20 (applied at runtime in the scanner).
type CAAutoRotateConfig struct {
	Enabled   bool          `yaml:"enabled,omitempty"`
	Interval  time.Duration `yaml:"interval,omitempty"`
	Threshold float64       `yaml:"threshold,omitempty"`
}

type ServerConfig struct {
	Listen     string      `yaml:"listen"`
	DataDir    string      `yaml:"data_dir"`
	DBPath     string      `yaml:"db_path"`
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

	// EnrollmentTokenTTL is the default lifetime applied to freshly minted
	// enrollment tokens (ADR 0004 / #75). Per-network overrides live in
	// the `network_config` table under the `enrollment_token_ttl` key.
	// Empty / unparseable value falls back to 24h.
	EnrollmentTokenTTL string `yaml:"enrollment_token_ttl,omitempty"`

	// CAAutoRotate configures the periodic CA auto-rotation scanner (issue #110).
	// Disabled by default — operators must opt in by setting Enabled=true.
	CAAutoRotate CAAutoRotateConfig `yaml:"ca_auto_rotate,omitempty"`

	// CookieSecure controls the `Secure` attribute on session and OIDC
	// state cookies (GHSA-rqfj-vv8r-xhqc). When unset, the effective
	// value is inferred from the TLS configuration: true if both
	// tls_cert and tls_key are populated, false otherwise. Operators
	// terminating TLS at a reverse proxy must set this to true
	// explicitly — `rate_limit.trust_proxy_header` is not a reliable
	// signal that the proxy speaks TLS to clients.
	CookieSecure *bool `yaml:"cookie_secure,omitempty"`

	// legacyAPIKey tracks whether `api_key:` was detected in the YAML during load.
	// The field was deprecated in favor of one-time stdout output from `init` and
	// recovery via `nebula-mgmt ops mint-admin-key`.
	legacyAPIKey bool
}

// CookieSecureResolved returns the effective Secure-cookie flag for this
// configuration. Explicit value wins; if unset, infer from the presence
// of TLS material on the server itself.
func (c ServerConfig) CookieSecureResolved() bool {
	if c.CookieSecure != nil {
		return *c.CookieSecure
	}
	return c.TLSCert != "" && c.TLSKey != ""
}

// HasLegacyAPIKey reports whether the YAML config contained a top-level
// `api_key:` key. The field was removed per #127 in favor of one-time
// stdout output and recovery via `nebula-mgmt ops mint-admin-key`.
func (c *ServerConfig) HasLegacyAPIKey() bool {
	return c.legacyAPIKey
}

// EnrollmentTokenTTLDuration returns the configured default token TTL parsed
// as a Go duration. Falls back to 24h when unset or invalid so the server
// always has a sane default.
func (c ServerConfig) EnrollmentTokenTTLDuration() time.Duration {
	if c.EnrollmentTokenTTL == "" {
		return 24 * time.Hour
	}
	d, err := time.ParseDuration(c.EnrollmentTokenTTL)
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
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
	Enabled          *bool                           `yaml:"enabled,omitempty"`
	TrustProxyHeader bool                            `yaml:"trust_proxy_header,omitempty"`
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
	DefaultRole   string   `yaml:"default_role,omitempty"`

	// RequireEmailVerified gates the post-callback email_verified claim
	// check. Pointer-bool to distinguish unset (default true: the IdP
	// must assert email_verified before the address counts toward
	// AllowedEmails) from an explicit `false` opt-out. The explicit
	// opt-out is the escape hatch for legacy IdPs that omit the claim
	// or send it in a shape HandleCallback can't decode (numeric,
	// nested object, etc). emailVerifiedRequired() resolves nil → true.
	RequireEmailVerified *bool `yaml:"require_email_verified,omitempty"`
}

// EmailVerifiedRequired reports whether HandleCallback must enforce the
// email_verified claim. Defaults to true when RequireEmailVerified is
// unset.
func (o *OIDCConfig) EmailVerifiedRequired() bool {
	if o == nil || o.RequireEmailVerified == nil {
		return true
	}
	return *o.RequireEmailVerified
}

// Validate refuses configurations that would silently auto-provision the
// first OIDC user as admin. Either constrain who can log in (allowed_groups
// or allowed_emails), or auto-provision as a lower-privileged role
// (default_role != "admin"). Setting default_role: admin with empty
// allowlists is permitted only as a deliberate two-field opt-in to
// "anyone-who-can-log-in-is-admin".
func (o *OIDCConfig) Validate() error {
	if o == nil || !o.Enabled {
		return nil
	}
	roleUnsetOrAdmin := o.DefaultRole == "" || o.DefaultRole == "admin"
	noAllowlist := len(o.AllowedGroups) == 0 && len(o.AllowedEmails) == 0
	if roleUnsetOrAdmin && noAllowlist {
		return fmt.Errorf(
			"oidc.default_role %q with no oidc.allowed_groups or oidc.allowed_emails would silently grant admin to any successful login; set oidc.default_role to a non-admin role (e.g. %q), or set at least one allowlist entry",
			o.DefaultRole, "user",
		)
	}
	return nil
}

// detectLegacyAPIKey reports whether the YAML bytes contain a top-level
// `api_key:` key (uncommented, no leading whitespace). Used during load
// to emit a deprecation warning — the field was removed per #127.
func detectLegacyAPIKey(b []byte) bool {
	for _, line := range bytes.Split(b, []byte("\n")) {
		// Strip everything after `#` (comment).
		if i := bytes.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		// Trim trailing whitespace; keep leading whitespace as-is
		// for the "top-level only" check.
		line = bytes.TrimRight(line, " \t\r")
		// Top-level YAML key — no leading whitespace.
		if bytes.HasPrefix(line, []byte("api_key:")) {
			return true
		}
	}
	return false
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-controlled config path is the documented API contract
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &ServerConfig{
		Listen:   ":8080",
		DataDir:  "/var/lib/nebula-mgmt",
		DBPath:   "/var/lib/nebula-mgmt/nebula.db",
		LogLevel: "info",
	}

	// Detect if YAML contains legacy `api_key:` field for deprecation warning.
	cfg.legacyAPIKey = detectLegacyAPIKey(data)

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

	if err := cfg.OIDC.Validate(); err != nil {
		return nil, err
	}

	if cfg.CAAutoRotate.Enabled {
		// Threshold: if non-zero, must be in (0, 1.0). Zero is OK (will apply default 0.20 at runtime).
		if cfg.CAAutoRotate.Threshold != 0 && (cfg.CAAutoRotate.Threshold <= 0 || cfg.CAAutoRotate.Threshold >= 1.0) {
			return nil, fmt.Errorf("ca_auto_rotate.threshold must be in range (0, 1.0), got %v", cfg.CAAutoRotate.Threshold)
		}
		// Interval: if non-zero, must be >= 1m. Zero is OK (will apply default 6h at runtime).
		if cfg.CAAutoRotate.Interval != 0 && cfg.CAAutoRotate.Interval < 1*time.Minute {
			return nil, fmt.Errorf("ca_auto_rotate.interval must be >= 1m, got %v", cfg.CAAutoRotate.Interval)
		}
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
