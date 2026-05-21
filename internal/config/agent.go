package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type AgentConfig struct {
	ServerURL        string        `yaml:"server_url"`
	DataDir          string        `yaml:"data_dir"`
	SigningKeyPath   string        `yaml:"signing_key_path"`
	PollInterval     time.Duration `yaml:"poll_interval"`
	NebulaConfigPath string        `yaml:"nebula_config_path"`
	NebulaPIDFile    string        `yaml:"nebula_pid_file"`
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

	if cfg.ServerURL == "" {
		return nil, errors.New("server_url is required")
	}

	return cfg, nil
}

// SaveAgentConfig writes cfg to path atomically (tmp + fsync + rename) with
// mode 0600. The parent directory is created with mode 0755 if missing.
func SaveAgentConfig(path string, cfg *AgentConfig) error {
	if cfg == nil {
		return errors.New("nil config")
	}
	if cfg.ServerURL == "" {
		return errors.New("server_url is required")
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".agent.yml.*")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp config: %w", err)
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
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("rename temp config: %w", err)
	}
	return nil
}
