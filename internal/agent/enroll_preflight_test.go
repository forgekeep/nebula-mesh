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

	err := Enroll(context.Background(), server.URL, "test-token", dataDir, signingKeyPath)
	if err == nil {
		t.Fatal("expected error for unwritable signing key dir, got nil")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error should mention permission denied; got %v", err)
	}
	if serverCalls.Load() != 0 {
		t.Errorf("server was hit %d times; pre-flight should fail before HTTP POST", serverCalls.Load())
	}
}
