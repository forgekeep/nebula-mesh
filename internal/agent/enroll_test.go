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

	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/enroll" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req struct {
			Token        string `json:"token"`
			PublicKeyPEM string `json:"public_key_pem"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		if req.Token == "" {
			t.Error("empty token in request")
		}
		if req.PublicKeyPEM == "" {
			t.Error("empty public key in request")
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

	err := Enroll(server.URL, "test-token", dir)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// Verify files
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

	// Check key permissions
	info, _ := os.Stat(filepath.Join(dir, "host.key"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("host.key permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestEnroll_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
	}))
	defer server.Close()

	err := Enroll(server.URL, "bad-token", t.TempDir())
	if err == nil {
		t.Fatal("expected error for server error response, got nil")
	}
}
