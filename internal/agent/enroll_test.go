package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEnroll_Success(t *testing.T) {
	dir := t.TempDir()
	agentDir := t.TempDir()
	signingKeyPath := filepath.Join(agentDir, "host.signing.key")

	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/enroll" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req struct {
			Token         string `json:"token"`
			PublicKeyPEM  string `json:"public_key_pem"`
			SigningPubPEM string `json:"signing_public_key_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode enroll request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if req.Token == "" {
			t.Error("empty token in request")
		}
		if req.PublicKeyPEM == "" {
			t.Error("empty public key in request")
		}
		if req.SigningPubPEM == "" {
			t.Error("empty signing public key in request")
		}

		resp := EnrollResponse{
			CertificatePEM:   "-----BEGIN NEBULA CERTIFICATE-----\ntest-cert\n-----END NEBULA CERTIFICATE-----",
			CACertificatePEM: "-----BEGIN NEBULA CERTIFICATE-----\ntest-ca\n-----END NEBULA CERTIFICATE-----",
			ConfigYAML:       "pki:\n  ca: /etc/nebula/ca.crt\n",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	err := Enroll(server.URL, "test-token", dir, signingKeyPath)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Nebula-side files live in dataDir.
	for _, name := range []string{"ca.crt", "host.crt", "host.key", "config.yml"} {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("file %s not found: %v", name, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("file %s is empty", name)
		}
	}

	// Signing key lives at the explicit signingKeyPath, NOT in dataDir.
	if _, err := os.Stat(filepath.Join(dir, "host.signing.key")); !os.IsNotExist(err) {
		t.Errorf("host.signing.key must NOT be in dataDir; got err = %v", err)
	}
	info, err := os.Stat(signingKeyPath)
	if err != nil {
		t.Fatalf("signing key not at %s: %v", signingKeyPath, err)
	}
	if info.Size() == 0 {
		t.Error("signing key file is empty")
	}

	// Check key permissions on both private keys.
	hostKeyInfo, _ := os.Stat(filepath.Join(dir, "host.key"))
	if hostKeyInfo.Mode().Perm() != 0o600 {
		t.Errorf("host.key permissions = %o, want 0600", hostKeyInfo.Mode().Perm())
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("host.signing.key permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestEnroll_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
	}))
	defer server.Close()

	err := Enroll(server.URL, "bad-token", t.TempDir(), filepath.Join(t.TempDir(), "host.signing.key"))
	if err == nil {
		t.Fatal("expected error for server error response, got nil")
	}
}
