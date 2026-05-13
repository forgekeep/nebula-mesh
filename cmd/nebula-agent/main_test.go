package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/config"
)

func TestResolveConfig_FileExists_FlagsIgnored(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	initial := config.DefaultAgentConfig()
	initial.ServerURL = "https://on-disk.example.com"
	if err := config.SaveAgentConfig(cfgPath, initial); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	var stderr bytes.Buffer
	cfg, err := resolveConfig(cfgPath, "https://cli.example.com", "", 0, false, &stderr)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if cfg.ServerURL != initial.ServerURL {
		t.Errorf("ServerURL = %q, want on-disk %q", cfg.ServerURL, initial.ServerURL)
	}
	if !strings.Contains(stderr.String(), "warning") {
		t.Errorf("expected warning about ignored flag in stderr; got %q", stderr.String())
	}

	// File on disk must not have been rewritten.
	loaded, err := config.LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.ServerURL != initial.ServerURL {
		t.Errorf("on-disk ServerURL changed to %q", loaded.ServerURL)
	}
}

func TestResolveConfig_FileExists_UpdateConfigOverwrites(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	initial := config.DefaultAgentConfig()
	initial.ServerURL = "https://old.example.com"
	if err := config.SaveAgentConfig(cfgPath, initial); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	var stderr bytes.Buffer
	cfg, err := resolveConfig(cfgPath, "https://new.example.com", "", 0, true, &stderr)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if cfg.ServerURL != "https://new.example.com" {
		t.Errorf("ServerURL = %q, want new", cfg.ServerURL)
	}

	loaded, err := config.LoadAgentConfig(cfgPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if loaded.ServerURL != "https://new.example.com" {
		t.Errorf("on-disk ServerURL = %q, want overwritten", loaded.ServerURL)
	}
}

func TestResolveConfig_FileMissing_WritesFromFlags(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sub", "agent.yml")

	var stderr bytes.Buffer
	cfg, err := resolveConfig(cfgPath, "https://fresh.example.com", filepath.Join(dir, "nebula"), 15*time.Second, false, &stderr)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	if cfg.ServerURL != "https://fresh.example.com" {
		t.Errorf("ServerURL = %q", cfg.ServerURL)
	}
	if cfg.DataDir != filepath.Join(dir, "nebula") {
		t.Errorf("DataDir = %q", cfg.DataDir)
	}
	if cfg.PollInterval != 15*time.Second {
		t.Errorf("PollInterval = %v", cfg.PollInterval)
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestResolveConfig_FileMissing_NoServer_Errors(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	var stderr bytes.Buffer
	_, err := resolveConfig(cfgPath, "", "", 0, false, &stderr)
	if err == nil {
		t.Fatal("expected error when config missing and --server unset")
	}
	if _, statErr := os.Stat(cfgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("config file was created on error path: %v", statErr)
	}
}

func TestResolveConfig_DoesNotPersistToken(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	var stderr bytes.Buffer
	// We never pass token into resolveConfig — but assert the file content
	// contains nothing token-shaped to lock the invariant from issue #67.
	_, err := resolveConfig(cfgPath, "https://srv.example.com", "", 0, false, &stderr)
	if err != nil {
		t.Fatalf("resolveConfig: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(strings.ToLower(string(data)), "token") {
		t.Errorf("config file contains token-shaped data: %s", data)
	}
}

func TestRun_FreshHost_NoTokenNoCert_Errors(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")
	dataDir := filepath.Join(dir, "nebula")

	// Seed an enrolled-but-cert-missing state: config exists, host.crt does not.
	cfg := config.DefaultAgentConfig()
	cfg.ServerURL = "https://srv.example.com"
	cfg.DataDir = dataDir
	if err := config.SaveAgentConfig(cfgPath, cfg); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var stderr bytes.Buffer
	err := run([]string{"--config", cfgPath}, &stderr, &stderr)
	if err == nil {
		t.Fatal("expected error: missing cert + no token")
	}
	if !strings.Contains(err.Error(), "--token") {
		t.Errorf("error message should mention --token hint; got %v", err)
	}
}

func TestRun_DeprecatedSubcommandWarning(t *testing.T) {
	var stderr bytes.Buffer
	// Both deprecated commands fail fast (missing flags), but the warning
	// must hit stderr regardless.
	_ = run([]string{"enroll"}, &stderr, &stderr)
	if !strings.Contains(stderr.String(), "deprecated") {
		t.Errorf("expected deprecation warning for enroll; got %q", stderr.String())
	}

	stderr.Reset()
	_ = run([]string{"run", "--config", "/nonexistent"}, &stderr, &stderr)
	if !strings.Contains(stderr.String(), "deprecated") {
		t.Errorf("expected deprecation warning for run; got %q", stderr.String())
	}
}
