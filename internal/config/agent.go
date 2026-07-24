package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/forgekeep/nebula-mesh/internal/fsutil"
)

type AgentConfig struct {
	ServerURL        string        `yaml:"server_url"`
	DataDir          string        `yaml:"data_dir"`
	SigningKeyPath   string        `yaml:"signing_key_path"`
	PollInterval     time.Duration `yaml:"poll_interval"`
	NebulaConfigPath string        `yaml:"nebula_config_path"`
	NebulaCAPath     string        `yaml:"nebula_ca_path,omitempty"`
	NebulaCertPath   string        `yaml:"nebula_cert_path,omitempty"`
	NebulaKeyPath    string        `yaml:"nebula_key_path,omitempty"`
	ImportSessionID  string        `yaml:"import_session_id,omitempty"`
	NebulaPIDFile    string        `yaml:"nebula_pid_file"`

	// NebulaReloadCommand, when set, is run through the system shell after
	// config/cert changes instead of sending SIGHUP to nebula_pid_file
	// (which it takes precedence over). Lets operators hook their service
	// manager (e.g. "systemctl reload nebula") and gives Windows — where
	// SIGHUP does not exist — a working reload path.
	NebulaReloadCommand string `yaml:"nebula_reload_command,omitempty"`

	// AllowInsecureHTTP opts out of the https-required guard on server_url.
	// Without it a plaintext http:// URL is only accepted for loopback
	// hosts — over any other network the enrollment token, certificates,
	// and the Nebula config the agent installs would transit in cleartext,
	// where an on-path attacker can steal the token or inject a malicious
	// config. Mirrors the server's allow_insecure_http (#179).
	AllowInsecureHTTP bool `yaml:"allow_insecure_http,omitempty"`
}

func (c *AgentConfig) ResolvedNebulaCAPath() string {
	if c.NebulaCAPath != "" {
		return c.NebulaCAPath
	}
	return filepath.Join(c.DataDir, "ca.crt")
}

func (c *AgentConfig) ResolvedNebulaCertPath() string {
	if c.NebulaCertPath != "" {
		return c.NebulaCertPath
	}
	return filepath.Join(c.DataDir, "host.crt")
}

func (c *AgentConfig) ResolvedNebulaKeyPath() string {
	if c.NebulaKeyPath != "" {
		return c.NebulaKeyPath
	}
	return filepath.Join(c.DataDir, "host.key")
}

// DefaultAgentConfig returns a config populated with the defaults the agent
// applies when fields are missing.
//
// SigningKeyPath defaults to /etc/nebula-agent/host.signing.key — agent's
// Ed25519 poll-signature key lives next to agent.yml, deliberately *not* in
// /etc/nebula where Nebula's own secrets live (ADR 0004 + #88).
func DefaultAgentConfig() *AgentConfig {
	return &AgentConfig{
		DataDir:          "/etc/nebula",
		SigningKeyPath:   "/etc/nebula-agent/host.signing.key",
		PollInterval:     30 * time.Second,
		NebulaConfigPath: "/etc/nebula/config.yml",
	}
}

func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-controlled config path is the documented API contract
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultAgentConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := ValidateAgentServerURL(cfg.ServerURL, cfg.AllowInsecureHTTP); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ValidateAgentServerURL guards the agent's management-server URL. The URL
// must be http/https with a host. A plaintext http:// URL is accepted only
// for a loopback host (local testing, an on-host TLS-terminating proxy)
// unless allowInsecure opts out — everywhere else the enrollment token and
// the host's rendered Nebula config would transit a real network in
// cleartext. The CLI and the server already carry the equivalent guards
// (#219, #179); this covers the agent.
//
// Exposed as a function rather than only a load-time check so the enroll
// path can validate the --server flag before the token is sent, when no
// config file exists yet.
func ValidateAgentServerURL(serverURL string, allowInsecure bool) error {
	if serverURL == "" {
		return errors.New("server_url is required")
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server_url %q: %w", serverURL, err)
	}
	switch u.Scheme {
	case "https":
		// Always fine.
	case "http":
		if !allowInsecure && !hostIsLoopback(u.Hostname()) {
			return fmt.Errorf("refusing plaintext http server_url %q: the enrollment token and rendered Nebula config would transit in cleartext; use https, or set allow_insecure_http: true (--insecure-http) to opt out", serverURL)
		}
	default:
		return fmt.Errorf("invalid server_url %q: scheme must be http or https", serverURL)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("invalid server_url %q: missing host", serverURL)
	}
	return nil
}

// hostIsLoopback reports whether host is the literal "localhost" or a
// loopback IP. Other hostnames are treated as non-loopback without
// resolving DNS, so the guard fails safe. Deliberately narrower than
// hostIsPrivate (server.go): a private-range address still crosses a real
// network, where cleartext is exactly the exposure this guard exists for.
func hostIsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// SaveAgentConfig writes cfg to path atomically (tmp + fsync + rename) with
// mode 0600. The parent directory is created with mode 0755 if missing.
// The server URL is validated with the same rules as LoadAgentConfig so a
// config that would be refused at the next startup is never written.
func SaveAgentConfig(path string, cfg *AgentConfig) error {
	if cfg == nil {
		return errors.New("nil config")
	}
	if err := ValidateAgentServerURL(cfg.ServerURL, cfg.AllowInsecureHTTP); err != nil {
		return err
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	// 0o600: agent.yml records the server URL and paths but no secrets; still
	// owner-only since it is the agent's private config.
	if err := fsutil.AtomicWriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
