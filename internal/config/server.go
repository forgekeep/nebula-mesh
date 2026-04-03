package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Listen      string `yaml:"listen"`
	DataDir     string `yaml:"data_dir"`
	DBPath      string `yaml:"db_path"`
	APIKey      string `yaml:"api_key"`
	UIPassword  string `yaml:"ui_password"`
	LogLevel    string `yaml:"log_level"`
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

	return cfg, nil
}
