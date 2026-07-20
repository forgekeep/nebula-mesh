package agent

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
)

// testEnrollCerts generates a real CA and host certificate pair for
// enrollment test fixtures. Returns (hostCertPEM, caCertPEM).
func testEnrollCerts(t *testing.T) (hostCertPEM, caCertPEM string) {
	t.Helper()
	caMgr, err := pki.NewCA("enroll-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(caMgr.Wipe)
	xPriv := make([]byte, 32)
	if _, err := rand.Read(xPriv); err != nil {
		t.Fatal(err)
	}
	xPub, err := curve25519.X25519(xPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	hostCert, err := caMgr.Sign(pki.SignRequest{
		Name: "enroll-test-host", PublicKey: xPub,
		Networks: []netip.Prefix{netip.MustParsePrefix("10.99.0.1/16")},
		Duration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	rawHostPEM, err := hostCert.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	rawCAPEM, err := caMgr.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	return string(rawHostPEM), string(rawCAPEM)
}

// enrollConfigYAML generates a Nebula config YAML with PKI paths matching
// the default Enroll() profile for the given data directory.
func enrollConfigYAML(dataDir string) string {
	return "pki:\n  ca: " + filepath.Join(dataDir, "ca.crt") +
		"\n  cert: " + filepath.Join(dataDir, "host.crt") +
		"\n  key: " + filepath.Join(dataDir, "host.key") + "\n"
}

// profileConfigYAML generates a Nebula config YAML with PKI paths matching
// the given agent profile.
func profileConfigYAML(p models.AgentProfile) string {
	return "pki:\n  ca: " + p.NebulaCAPath +
		"\n  cert: " + p.NebulaCertPath +
		"\n  key: " + p.NebulaKeyPath + "\n"
}

func TestEnroll_Success(t *testing.T) {
	dir := t.TempDir()
	agentDir := t.TempDir()
	signingKeyPath := filepath.Join(agentDir, "host.signing.key")
	hostCertPEM, caCertPEM := testEnrollCerts(t)

	// Mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/enroll" {
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
			CertificatePEM:   hostCertPEM,
			CACertificatePEM: caCertPEM,
			ConfigYAML:       enrollConfigYAML(dir),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	err := Enroll(context.Background(), server.URL, "test-token", dir, signingKeyPath, "")
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

func TestEnrollAcknowledgesInitialConfigVersion(t *testing.T) {
	dataDir := t.TempDir()
	signingPath := filepath.Join(t.TempDir(), "host.signing.key")
	certificatePEM, caCertPEM := testEnrollCerts(t)
	rendered := "pki:\n  ca: " + filepath.Join(dataDir, "ca.crt") + "\n  cert: " + filepath.Join(dataDir, "host.crt") + "\n  key: " + filepath.Join(dataDir, "host.key") + "\n"
	var acknowledgements atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/enroll":
			_ = json.NewEncoder(response).Encode(EnrollResponse{
				CertificatePEM: certificatePEM, CACertificatePEM: caCertPEM, ConfigYAML: rendered, ConfigVersion: 4,
			})
		case "/api/v1/agent/config-ack/4":
			if request.Header.Get("X-Nebula-Signature") == "" || request.Header.Get("X-Nebula-Fingerprint") == "" {
				t.Error("initial config ack is unsigned")
			}
			acknowledgements.Add(1)
			response.WriteHeader(http.StatusOK)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	if err := Enroll(t.Context(), server.URL, "nme_token", dataDir, signingPath, ""); err != nil {
		t.Fatal(err)
	}
	if acknowledgements.Load() != 1 {
		t.Fatalf("initial acknowledgements = %d", acknowledgements.Load())
	}
}

func TestEnroll_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid token"})
	}))
	defer server.Close()

	err := Enroll(context.Background(), server.URL, "bad-token", t.TempDir(), filepath.Join(t.TempDir(), "host.signing.key"), "")
	if err == nil {
		t.Fatal("expected error for server error response, got nil")
	}
}
