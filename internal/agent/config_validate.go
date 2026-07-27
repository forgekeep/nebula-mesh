package agent

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	nebulaconfig "github.com/slackhq/nebula/config"
)

// validateConfigPKIPaths parses a Nebula config YAML and verifies that
// pki.ca, pki.cert, and pki.key match the expected paths. This prevents
// a compromised or buggy server from redirecting the Nebula daemon to
// read key material from arbitrary paths (#300).
func validateConfigPKIPaths(configYAML, configDir, caPath, certPath, keyPath string) error {
	file, err := os.CreateTemp(configDir, ".nebula-agent-validate-")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure temp config: %w", err)
	}
	if _, err := file.WriteString(configYAML); err != nil {
		_ = file.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync temp config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	configuration := nebulaconfig.NewC(logger)
	if err := configuration.Load(path); err != nil {
		return fmt.Errorf("invalid config YAML: %w", err)
	}
	expected := map[string]string{
		"pki.ca": caPath, "pki.cert": certPath, "pki.key": keyPath,
	}
	for key, want := range expected {
		if got := configuration.GetString(key, ""); got != want {
			return fmt.Errorf("config %s path %q does not match expected %q", key, got, want)
		}
	}
	return nil
}
