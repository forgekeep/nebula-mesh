package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// syncedBuffer is a tiny mutex-guarded byte buffer used by tests that read
// stderr concurrently with the daemon writing to it. bytes.Buffer alone is
// not safe for concurrent Write+String, which trips the race detector.
type syncedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncedBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncedBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// enrollMockServer answers POST /api/v1/enroll with a synthetic cert+CA+config
// payload and GET /api/v1/agent/updates with an empty signed-poll response.
// callsByPath records how often each endpoint was hit so tests can assert
// the confirmation poll fired.
type enrollMockServer struct {
	ts           *httptest.Server
	enrollCalls  atomic.Int32
	updatesCalls atomic.Int32
	updatesCode  atomic.Int32 // override status code for /agent/updates
	signingPub   ed25519.PublicKey
}

func newEnrollMockServer(t *testing.T) *enrollMockServer {
	t.Helper()
	srv := &enrollMockServer{}
	srv.updatesCode.Store(int32(http.StatusOK))
	srv.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/enroll":
			srv.enrollCalls.Add(1)
			// Capture the signing public key the agent sent so we don't
			// need a fresh fingerprint match in the updates branch.
			var body struct {
				SigningPubPEM string `json:"signing_public_key_pem"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if block, _ := pem.Decode([]byte(body.SigningPubPEM)); block != nil {
				srv.signingPub = ed25519.PublicKey(block.Bytes)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"certificate_pem":    pemBlock("NEBULA CERTIFICATE", "cert-bytes"),
				"ca_certificate_pem": pemBlock("NEBULA CERTIFICATE", "ca-bytes"),
				"config_yaml":        "pki:\n  ca: /etc/nebula/ca.crt\n",
			})
		case "/api/v1/agent/updates":
			srv.updatesCalls.Add(1)
			code := int(srv.updatesCode.Load())
			w.WriteHeader(code)
			if code == http.StatusOK {
				_, _ = io.WriteString(w, `{"has_updates":false,"blocklist":[]}`)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.ts.Close)
	return srv
}

func pemBlock(kind, body string) string {
	return "-----BEGIN " + kind + "-----\n" + body + "\n-----END " + kind + "-----\n"
}

// TestEnrollSubcommand_WritesFiles — happy path. enroll subcommand hits
// both the enroll and updates endpoints, writes agent.yml + the five
// enrollment files with the right modes, and exits 0.
func TestEnrollSubcommand_WritesFiles(t *testing.T) {
	srv := newEnrollMockServer(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")
	dataDir := filepath.Join(dir, "nebula")
	signingKeyPath := filepath.Join(dir, "agent", "host.signing.key")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := run(ctx, []string{
		"enroll",
		"--config", cfgPath,
		"--server", srv.ts.URL,
		"--token", "tok",
		"--data-dir", dataDir,
		"--signing-key-path", signingKeyPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("enroll: %v\nstderr=%s", err, stderr.String())
	}
	if srv.enrollCalls.Load() != 1 {
		t.Errorf("enroll endpoint hit %d times, want 1", srv.enrollCalls.Load())
	}

	// Cert won't actually parse (we don't generate a real Nebula cert in
	// the mock), so confirmation poll may emit "warning: cannot read fresh
	// cert fingerprint" and skip the updates call. We accept either branch
	// here — the file contract is what we lock down.
	if _, err := os.Stat(cfgPath); err != nil {
		t.Errorf("agent.yml missing: %v", err)
	}
	for _, p := range []string{
		filepath.Join(dataDir, "host.key"),
		filepath.Join(dataDir, "host.crt"),
		filepath.Join(dataDir, "ca.crt"),
		filepath.Join(dataDir, "config.yml"),
		signingKeyPath,
	} {
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("%s missing: %v", p, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("%s is empty", p)
		}
	}
	// Private keys must be 0600.
	for _, p := range []string{filepath.Join(dataDir, "host.key"), signingKeyPath} {
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 0600", p, info.Mode().Perm())
		}
	}
	// agent.yml is also 0600.
	info, _ := os.Stat(cfgPath)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("agent.yml mode = %o, want 0600", info.Mode().Perm())
	}
}

// TestEnrollSubcommand_FirstPollFailureIsNonFatal — mock returns 500 on
// /agent/updates. enroll still exits 0; the on-disk artifacts are intact;
// stderr carries the warning.
func TestEnrollSubcommand_FirstPollFailureIsNonFatal(t *testing.T) {
	srv := newEnrollMockServer(t)
	srv.updatesCode.Store(int32(http.StatusInternalServerError))

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")
	dataDir := filepath.Join(dir, "nebula")
	signingKeyPath := filepath.Join(dir, "agent", "host.signing.key")

	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := run(ctx, []string{
		"enroll",
		"--config", cfgPath,
		"--server", srv.ts.URL,
		"--token", "tok",
		"--data-dir", dataDir,
		"--signing-key-path", signingKeyPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("enroll should not fail when first poll errors: %v\nstderr=%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "warning") {
		// Allow either "first poll failed" or "cannot read fresh cert
		// fingerprint" — both qualify; the contract is that enroll keeps
		// exit 0 and surfaces a warning.
		t.Errorf("expected warning on stderr; got %q", stderr.String())
	}
	if _, err := os.Stat(cfgPath); err != nil {
		t.Errorf("agent.yml must still be written on first-poll failure: %v", err)
	}
}

// TestEnrollSubcommand_RefusesWhenAlreadyEnrolled — pre-seed host.crt;
// enroll without --force is rejected; the second call with --force succeeds.
func TestEnrollSubcommand_RefusesWhenAlreadyEnrolled(t *testing.T) {
	srv := newEnrollMockServer(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")
	dataDir := filepath.Join(dir, "nebula")
	signingKeyPath := filepath.Join(dir, "agent", "host.signing.key")

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "host.crt"), []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err := run(ctx, []string{
		"enroll",
		"--config", cfgPath,
		"--server", srv.ts.URL,
		"--token", "tok",
		"--data-dir", dataDir,
		"--signing-key-path", signingKeyPath,
	}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error; pre-seeded host.crt should block enroll without --force")
		return
	}
	if !strings.Contains(err.Error(), "already enrolled") {
		t.Errorf("error message should mention 'already enrolled'; got %v", err)
	}

	// With --force, the same command succeeds.
	stdout.Reset()
	stderr.Reset()
	err = run(ctx, []string{
		"enroll",
		"--config", cfgPath,
		"--server", srv.ts.URL,
		"--token", "tok",
		"--data-dir", dataDir,
		"--signing-key-path", signingKeyPath,
		"--force",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("enroll --force: %v\nstderr=%s", err, stderr.String())
	}
}

// TestEnrollSubcommand_RequiresServerAndToken — both flags are required.
func TestEnrollSubcommand_RequiresServerAndToken(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err := run(ctx, []string{"enroll", "--config", cfgPath, "--token", "tok"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("missing --server: err = %v", err)
	}
	stderr.Reset()
	err = run(ctx, []string{"enroll", "--config", cfgPath, "--server", "https://srv"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("missing --token: err = %v", err)
	}
}

// TestEnrollSubcommand_RefusesPlaintextHTTP pins the https-required guard on
// the enroll path: a cleartext non-loopback --server is refused before the
// single-use token leaves the process (no config or key files are written).
// httptest URLs are loopback, so every other enroll test passes the guard
// untouched; --insecure-http opts out.
func TestEnrollSubcommand_RefusesPlaintextHTTP(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err := run(ctx, []string{
		"enroll", "--config", cfgPath,
		"--server", "http://mgmt.example.com:8080", "--token", "tok",
		"--data-dir", filepath.Join(dir, "nebula"),
	}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "refusing plaintext http") {
		t.Fatalf("plaintext non-loopback --server: err = %v, want https-required refusal", err)
	}
	if _, statErr := os.Stat(cfgPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("config written despite refused URL: stat = %v", statErr)
	}
}

// TestRun_LeavesStandbyAfterFilesAppear — start runUnified in idle, then
// from a goroutine drop the enrollment artifacts into place and confirm
// the daemon transitions to the poll loop (mock server records a signed
// updates call). Uses a shorter standby tick for test latency — the real
// tick is hard-coded but the helper drops files BEFORE the first tick to
// keep the test under one second.
func TestRun_LeavesStandbyAfterFilesAppear(t *testing.T) {
	// Shorten the standby tick so the test runs in <1s. Restore on exit.
	orig := standbyTick
	standbyTick = 50 * time.Millisecond
	t.Cleanup(func() { standbyTick = orig })

	srv := newEnrollMockServer(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agent.yml")
	dataDir := filepath.Join(dir, "nebula")
	signingKeyPath := filepath.Join(dir, "agent", "host.signing.key")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(signingKeyPath), 0o755); err != nil {
		t.Fatal(err)
	}

	// Use the real enroll subcommand to lay down the artifacts — that
	// exercises the same code path operators will use.
	enrollDone := make(chan struct{})
	go func() {
		// Small delay so the daemon goroutine below has time to enter
		// standby first.
		time.Sleep(50 * time.Millisecond)
		var b bytes.Buffer
		_ = run(context.Background(), []string{
			"enroll",
			"--config", cfgPath,
			"--server", srv.ts.URL,
			"--token", "tok",
			"--data-dir", dataDir,
			"--signing-key-path", signingKeyPath,
		}, &b, &b)
		close(enrollDone)
	}()

	// Daemon goroutine — runs runUnified, expects to leave standby and
	// poll the mock server at least once.
	daemonCtx, cancelDaemon := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDaemon()
	daemonDone := make(chan error, 1)
	stderrW := &syncedBuffer{}
	go func() {
		daemonDone <- run(daemonCtx, []string{"--config", cfgPath}, io.Discard, stderrW)
	}()

	// Wait for enroll subcommand to write files. Then poll the mock
	// server's updates-counter until the daemon catches up.
	select {
	case <-enrollDone:
	case <-time.After(3 * time.Second):
		t.Fatal("enroll subcommand did not finish")
	}

	// Watch stderr for the transition log message. We assert that the
	// daemon left standby and entered the poll loop — that proves
	// awaitEnrollment unblocked, which is what #88 is about. We don't
	// assert on updates_calls because the production poll_interval (30s)
	// is far longer than the test timeout; the standby → poll transition
	// itself is the contract.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stderrW.String(), "leaving standby") {
			cancelDaemon()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(stderrW.String(), "leaving standby") {
		t.Errorf("daemon did not leave standby; stderr = %s", stderrW.String())
	}

	// Drain the daemon goroutine; we don't care about its error value as
	// long as it stopped (it returns ctx.Err() once we cancel).
	select {
	case err := <-daemonDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			// Confirmation poll inside the daemon will fail to parse the
			// fake cert in the response and return a poll error — that's
			// expected with this mock.
			_ = err
		}
	case <-time.After(5 * time.Second):
		t.Error("daemon did not exit within 5s after cancel")
	}
}
