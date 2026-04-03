package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type AgentConfig struct {
	ServerURL        string        `yaml:"server_url"`
	DataDir          string        `yaml:"data_dir"`
	PollInterval     time.Duration `yaml:"poll_interval"`
	NebulaConfigPath string        `yaml:"nebula_config_path"`
	NebulaPIDFile    string        `yaml:"nebula_pid_file"`
}

func LoadAgentConfig(path string) (*AgentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &AgentConfig{
		DataDir:          "/etc/nebula",
		PollInterval:     30 * time.Second,
		NebulaConfigPath: "/etc/nebula/config.yml",
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.ServerURL == "" {
		return nil, errors.New("server_url is required")
	}

	return cfg, nil
}
