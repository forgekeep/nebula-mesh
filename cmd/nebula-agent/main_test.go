package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	cfg, err := resolveConfig(cfgPath, "https://cli.example.com", "", 0, false, false, &stderr)
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
	cfg, err := resolveConfig(cfgPath, "https://new.example.com", "", 0, true, false, &stderr)
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
	cfg, err := resolveConfig(cfgPath, "https://fresh.example.com", filepath.Join(dir, "nebula"), 15*time.Second, false, false, &stderr)
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
	// Windows has no POSIX permission bits; Go reports 0666 regardless of chmod.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("config mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestResolveConfig_FileMissing_NoServer_Errors(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	var stderr bytes.Buffer
	_, err := resolveConfig(cfgPath, "", "", 0, false, false, &stderr)
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
	_, err := resolveConfig(cfgPath, "https://srv.example.com", "", 0, false, false, &stderr)
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

// TestRun_StandbyWarnsOnRejectedHTTPConfig — an upgraded host whose
// pre-guard agent.yml carries a plaintext http:// non-loopback server_url
// must not silently park in standby. The daemon load path refuses the
// config and the standby entry logs the rejection at Warn with the
// remediation, so the operator sees why polling never starts.
func TestRun_StandbyWarnsOnRejectedHTTPConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	// Write the file directly: SaveAgentConfig would reject the http:// URL,
	// so this models a config written by an older release.
	yaml := "server_url: \"http://mgmt.example.com:8080\"\ndata_dir: \"" + filepath.Join(dir, "nebula") + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := run(ctx, []string{"--config", cfgPath}, &stderr, &stderr)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context deadline/cancel", err)
	}
	out := stderr.String()
	if !strings.Contains(out, "config present but rejected") {
		t.Errorf("stderr should warn that the config was rejected; got %q", out)
	}
	if !strings.Contains(out, "allow_insecure_http") {
		t.Errorf("stderr should name the opt-out; got %q", out)
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

// TestRun_UnknownSubcommand_FailsFast pins the fix for the enrollment trap:
// a mistyped subcommand used to fall through to runUnified, where Go's flag
// parser stops at the first positional and silently discarded --server and
// --token. The agent then parked in standby forever and never contacted the
// server, which reads as a server-side enrollment failure. It must be a
// usage error instead.
func TestRun_UnknownSubcommand_FailsFast(t *testing.T) {
	var stdout, stderr bytes.Buffer
	// A generous deadline: if the command still parks in standby the test
	// fails on the error value, not on the timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := run(ctx, []string{"enrool", "--server", "https://mgmt.example.com", "--token-file", "/nonexistent"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("mistyped subcommand returned nil; want a usage error")
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("mistyped subcommand parked in standby instead of failing: %v", err)
	}
	if !strings.Contains(err.Error(), "unknown command") || strings.Contains(err.Error(), "enrool") {
		t.Errorf("error = %v, want an unknown-command error without the command value", err)
	}
	if !strings.Contains(stderr.String(), "nebula-agent enroll") {
		t.Errorf("usage not printed on unknown command; stderr = %q", stderr.String())
	}
}

// TestRun_UnknownSubcommandDoesNotEchoUnclassifiedInput — SEC-DIAGNOSTIC-001:
// command words can be passwords, API keys, or current and legacy enrollment
// tokens, so neither the error nor CLI output may copy them.
func TestRun_UnknownSubcommandDoesNotEchoUnclassifiedInput(t *testing.T) {
	values := []string{
		"correct-horse-battery-staple",
		"test-api-key-ThisIsNotReal",
		"legacy-enrollment-token-ThisIsNotReal",
		"nme_ThisIsNotARealTokenJustTestData_0123456789",
		"nmi_ThisIsNotARealTokenJustTestData_0123456789",
	}
	for _, value := range values {
		t.Run(value, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := run(ctx, []string{value, "--server", "https://mgmt.example.com"}, &stdout, &stderr)
			if err == nil {
				t.Fatal("value-as-subcommand returned nil; want a usage error")
			}
			if strings.Contains(err.Error(), value) {
				t.Errorf("unclassified input leaked into error message: %v", err)
			}
			if strings.Contains(stdout.String(), value) || strings.Contains(stderr.String(), value) {
				t.Errorf("unclassified input leaked into output: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

// TestRun_LeadingFlagStillReachesUnified guards the daemon entrypoint: only a
// bare word is treated as a subcommand, so `nebula-agent --config X` (and the
// help/version flags) must keep working exactly as before.
func TestRun_LeadingFlagStillReachesUnified(t *testing.T) {
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := run(ctx, []string{"--config", filepath.Join(t.TempDir(), "agent.yml")}, &stdout, &stderr)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the standby loop to run until the deadline", err)
	}
	if strings.Contains(stderr.String(), "unknown command") {
		t.Errorf("leading flag misread as a subcommand; stderr = %q", stderr.String())
	}
}

// TestRun_PositionalArgAfterFlags_Errors — a stray operand means Go stopped
// parsing there and every later flag was dropped. Both the enroll subcommand
// and the unified daemon path must reject it rather than run with a partial
// flag set.
func TestRun_PositionalArgAfterFlags_Errors(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"enroll", []string{"enroll", "--server", "https://mgmt.example.com", "correct-horse-battery-staple", "--token", "tok"}},
		{"unified", []string{"--config", "/nonexistent", "correct-horse-battery-staple", "--server", "https://mgmt.example.com"}},
		{"legacy run", []string{"run", "--config", "/nonexistent", "correct-horse-battery-staple"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := run(ctx, test.args, &stdout, &stderr)
			if err == nil {
				t.Fatal("stray positional returned nil; want a usage error")
			}
			if !strings.Contains(err.Error(), "unexpected argument") || strings.Contains(err.Error(), "correct-horse-battery-staple") {
				t.Errorf("error = %v, want a positional-argument error without the value", err)
			}
			if strings.Contains(stdout.String(), "correct-horse-battery-staple") || strings.Contains(stderr.String(), "correct-horse-battery-staple") {
				t.Errorf("positional value leaked into output: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}
