package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/config"
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

// TestRun_StandbyWhenConfigMissing — daemon launched with no flags and no
// existing config sits in standby instead of failing fast. Context-cancel
// (the SIGTERM analog under test) must return ctx.Err(), not a wrapped
// error.
func TestRun_StandbyWhenConfigMissing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := run(ctx, []string{"--config", cfgPath}, &stderr, &stderr)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.DeadlineExceeded or Canceled", err)
	}
	if !strings.Contains(stderr.String(), "standby") {
		t.Errorf("stderr should mention standby; got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "nebula-agent enroll") {
		t.Errorf("stderr should hint at `nebula-agent enroll`; got %q", stderr.String())
	}
}

// TestRun_StandbyWhenCertMissing — config exists, but host.crt/signing-key
// are not on disk yet. Same standby behavior as TestRun_StandbyWhenConfigMissing.
func TestRun_StandbyWhenCertMissing(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")
	dataDir := filepath.Join(dir, "nebula")

	cfg := config.DefaultAgentConfig()
	cfg.ServerURL = "https://srv.example.com"
	cfg.DataDir = dataDir
	cfg.SigningKeyPath = filepath.Join(dir, "agent", "host.signing.key")
	if err := config.SaveAgentConfig(cfgPath, cfg); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := run(ctx, []string{"--config", cfgPath}, &stderr, &stderr)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.DeadlineExceeded or Canceled", err)
	}
	if !strings.Contains(stderr.String(), "standby") {
		t.Errorf("stderr should mention standby; got %q", stderr.String())
	}
}

// TestCheckEnrollment_ReturnsCfgWhenReady — unit-level coverage of the
// state-machine helper. When config + cert + signing key are all present,
// it returns the loaded config and an empty reason.
func TestCheckEnrollment_ReturnsCfgWhenReady(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")
	dataDir := filepath.Join(dir, "nebula")
	skPath := filepath.Join(dir, "agent", "host.signing.key")

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(skPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "host.crt"), []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(skPath, []byte("sk"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.DefaultAgentConfig()
	cfg.ServerURL = "https://srv.example.com"
	cfg.DataDir = dataDir
	cfg.SigningKeyPath = skPath
	if err := config.SaveAgentConfig(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}

	got, reason := checkEnrollment(cfgPath)
	if got == nil {
		t.Fatalf("got nil cfg with reason %q", reason)
		return
	}
	if reason != "" {
		t.Errorf("reason = %q, want empty", reason)
	}
	if got.ServerURL != "https://srv.example.com" {
		t.Errorf("ServerURL = %q", got.ServerURL)
	}
}

// TestRun_DeprecatedSubcommand_Run pins the deprecation warning on the
// remaining legacy subcommand. `enroll` is no longer deprecated after #88,
// so its branch is exercised separately (see TestEnrollSubcommand_* below).
func TestRun_DeprecatedSubcommand_Run(t *testing.T) {
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = run(ctx, []string{"run", "--config", "/nonexistent"}, &stderr, &stderr)
	if !strings.Contains(stderr.String(), "deprecated") {
		t.Errorf("expected deprecation warning for run; got %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "`nebula-agent enroll` is deprecated") {
		t.Errorf("enroll subcommand should NOT print deprecation warning; got %q", stderr.String())
	}
}
