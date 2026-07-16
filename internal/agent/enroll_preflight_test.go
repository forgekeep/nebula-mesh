//go:build !windows

package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestEnroll_PreflightFailsBeforeServerCall(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test relies on filesystem permissions; root bypasses them")
	}

	var serverCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverCalls.Add(1)
		t.Errorf("server must not be called before pre-flight passes")
	}))
	defer server.Close()

	parentDir := t.TempDir()
	readOnly := filepath.Join(parentDir, "ro")
	if err := os.Mkdir(readOnly, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o755) })

	dataDir := t.TempDir()
	signingKeyPath := filepath.Join(readOnly, "agent", "host.signing.key")

	err := Enroll(context.Background(), server.URL, "test-token", dataDir, signingKeyPath, "")
	if err == nil {
		t.Fatal("expected error for unwritable signing key dir, got nil")
		return
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error should mention permission denied; got %v", err)
	}
	if serverCalls.Load() != 0 {
		t.Errorf("server was hit %d times; pre-flight should fail before HTTP POST", serverCalls.Load())
	}
}

func TestReenroll_CustomPathPreflightFailsBeforeServerCall(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test relies on filesystem permissions; root bypasses them")
	}

	var serverCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		serverCalls.Add(1)
	}))
	t.Cleanup(server.Close)

	root := t.TempDir()
	readOnly := filepath.Join(root, "read-only")
	if err := os.Mkdir(readOnly, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o755) })
	profile := models.AgentProfile{
		NebulaConfigPath: filepath.Join(root, "shared", "config.yml"),
		NebulaCAPath:     filepath.Join(root, "shared", "ca.crt"),
		NebulaCertPath:   filepath.Join(root, "shared", "host.crt"),
		NebulaKeyPath:    filepath.Join(readOnly, "host.key"),
		ConfigAckV1:      true,
	}
	err := Reenroll(t.Context(), server.URL, "token", ReenrollOptions{
		DataDir: root, SigningKeyPath: filepath.Join(root, "shared", "signing.key"), Profile: profile,
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("error = %v, want permission denied", err)
	}
	if serverCalls.Load() != 0 {
		t.Fatalf("server calls = %d, want 0", serverCalls.Load())
	}
}
