package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// captureEnrollSecrets installs the test observer and returns a pointer that
// receives the live secrets container when Enroll returns. The observer runs
// before the deferred wipe, so the captured slices alias the real buffers and
// read as zeros only if the wipe actually ran.
func captureEnrollSecrets(t *testing.T) **enrollmentSecrets {
	t.Helper()
	var captured *enrollmentSecrets
	enrollSecretsObserverForTest = func(s *enrollmentSecrets) {
		if !allZero(s.privKey) || !allZero(s.signingPriv) {
			// Sanity: the secrets are still live at observation time —
			// otherwise the zero assertions below would pass vacuously.
			captured = s
			return
		}
		t.Error("secrets already zero before the deferred wipe — observer mis-ordered")
	}
	t.Cleanup(func() { enrollSecretsObserverForTest = nil })
	return &captured
}

// TestEnroll_ZeroizesPrivateKeys verifies that after a successful enrollment
// every heap copy of the X25519 host key and the Ed25519 signing key (raw and
// PEM) has been overwritten with zeros (L4, 2026-06-12 audit; same standard
// as the server's caMgr.Wipe — GHSA-8h84 / #181).
func TestEnroll_ZeroizesPrivateKeys(t *testing.T) {
	dir := t.TempDir()
	signingKeyPath := filepath.Join(t.TempDir(), "host.signing.key")
	hostCertPEM, caCertPEM := testEnrollCerts(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := EnrollResponse{
			CertificatePEM:   hostCertPEM,
			CACertificatePEM: caCertPEM,
			ConfigYAML:       enrollConfigYAML(dir),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	captured := captureEnrollSecrets(t)
	if err := Enroll(context.Background(), server.URL, "test-token", dir, signingKeyPath, ""); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	assertSecretsWiped(t, *captured)
}

// TestEnroll_ZeroizesPrivateKeysOnError pins the error path: a server-side
// failure after key generation must still wipe the generated material.
func TestEnroll_ZeroizesPrivateKeysOnError(t *testing.T) {
	dir := t.TempDir()
	signingKeyPath := filepath.Join(t.TempDir(), "host.signing.key")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"token expired"}`, http.StatusUnauthorized)
	}))
	defer server.Close()

	captured := captureEnrollSecrets(t)
	if err := Enroll(context.Background(), server.URL, "stale-token", dir, signingKeyPath, ""); err == nil {
		t.Fatal("expected enrollment error")
	}
	if *captured == nil {
		t.Fatal("observer not invoked")
	}
	// On the early-error path only the raw keys exist; PEM fields are nil
	// and Zeroize(nil) is a no-op.
	if !allZero((*captured).privKey) {
		t.Error("X25519 private key not zeroized on error path")
	}
	if !allZero((*captured).signingPriv) {
		t.Error("Ed25519 signing key not zeroized on error path")
	}
}

func assertSecretsWiped(t *testing.T, s *enrollmentSecrets) {
	t.Helper()
	if s == nil {
		t.Fatal("observer not invoked")
	}
	checks := []struct {
		name string
		buf  []byte
	}{
		{"privKey", s.privKey},
		{"privKeyPEM", s.privKeyPEM},
		{"signingPriv", s.signingPriv},
		{"signingPrivPEM", s.signingPrivPEM},
	}
	for _, c := range checks {
		if len(c.buf) == 0 {
			t.Errorf("%s never populated — assertion vacuous", c.name)
			continue
		}
		if !allZero(c.buf) {
			t.Errorf("%s not zeroized after Enroll", c.name)
		}
	}
}
