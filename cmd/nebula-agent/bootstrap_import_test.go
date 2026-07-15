package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	meshagent "github.com/forgekeep/nebula-mesh/internal/agent"
	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/importproof"
	"github.com/forgekeep/nebula-mesh/internal/pki"
)

func TestEnrollExistingImportRequiresConfirmationBeforeNetwork(t *testing.T) {
	fixture := newCommandImportFixture(t)
	server := newCommandImportServer(t)
	var stdout, stderr bytes.Buffer
	err := run(t.Context(), fixture.args(server.URL, false), &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("error = %v, want confirmation requirement", err)
	}
	if server.calls.Load() != 0 {
		t.Fatalf("network calls before confirmation = %d", server.calls.Load())
	}
	if _, err := os.Stat(fixture.agentConfigPath); !os.IsNotExist(err) {
		t.Fatalf("agent config written before confirmation: %v", err)
	}
}

func TestEnrollExistingImportPreservesNebulaFilesAndPersistsProfile(t *testing.T) {
	fixture := newCommandImportFixture(t)
	server := newCommandImportServer(t)
	before := fixture.readNebulaFiles(t)
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), fixture.args(server.URL, true), &stdout, &stderr); err != nil {
		t.Fatalf("import: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	if server.imports.Load() != 1 || server.proofFailures.Load() != 0 {
		t.Fatalf("imports=%d proof failures=%d", server.imports.Load(), server.proofFailures.Load())
	}
	after := fixture.readNebulaFiles(t)
	for path, contents := range before {
		if !bytes.Equal(contents, after[path]) {
			t.Errorf("Nebula file changed during import: %s", path)
		}
	}
	loaded, err := config.LoadAgentConfig(fixture.agentConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.NebulaConfigPath != fixture.nebulaConfigPath || loaded.NebulaCAPath != fixture.caPath ||
		loaded.NebulaCertPath != fixture.certPath || loaded.NebulaKeyPath != fixture.keyPath ||
		loaded.ImportSessionID != "session-command" {
		t.Fatalf("persisted config = %#v", loaded)
	}
	configBytes, err := os.ReadFile(fixture.agentConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(configBytes, []byte("nmi_command-token")) || bytes.Contains(configBytes, []byte("token:")) {
		t.Fatalf("agent config leaked import token: %s", configBytes)
	}
	if !strings.Contains(stdout.String(), "import successful") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestUnifiedExistingImportTransitionsToPendingPoll(t *testing.T) {
	fixture := newCommandImportFixture(t)
	server := newCommandImportServer(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	args := []string{
		"--config", fixture.agentConfigPath, "--server", server.URL,
		"--token-file", fixture.tokenFilePath, "--data-dir", filepath.Dir(fixture.nebulaConfigPath),
		"--nebula-config-path", fixture.nebulaConfigPath, "--yes", "--poll-interval", "10ms",
	}
	var stderr bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- runUnified(ctx, args, &stderr) }()
	select {
	case <-server.polled:
		cancel()
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("unified import did not enter pending poll")
	}
	if err := <-done; err != nil {
		t.Fatalf("runUnified: %v\nstderr=%s", err, stderr.String())
	}
	loaded, err := config.LoadAgentConfig(fixture.agentConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ImportSessionID != "session-command" || loaded.NebulaCertPath != fixture.certPath {
		t.Fatalf("persisted unified config = %#v", loaded)
	}
	if strings.Contains(stderr.String(), "nmi_command-token") {
		t.Fatalf("stderr leaked import token: %s", stderr.String())
	}
	wantFingerprint, err := meshagent.ReadCertFingerprintAt(fixture.certPath)
	if err != nil {
		t.Fatal(err)
	}
	if server.pollFingerprint.Load() != wantFingerprint {
		t.Fatalf("restart poll fingerprint = %v, want %s", server.pollFingerprint.Load(), wantFingerprint)
	}
}

func TestBootstrapPurposeStateRefusesBeforeNetwork(t *testing.T) {
	tests := []struct {
		name     string
		existing bool
		token    string
		want     string
	}{
		{name: "fresh import", token: "nmi_value", want: "requires an existing complete"},
		{name: "existing enrollment", existing: true, token: "nme_value", want: "requires an import token"},
		{name: "existing legacy enrollment", existing: true, token: "legacy-value", want: "requires an import token"},
		{name: "unknown prefix", token: "nmz_value", want: "unknown bootstrap token purpose"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newCommandImportServer(t)
			dir := t.TempDir()
			configPath := filepath.Join(dir, "agent.yml")
			nebulaConfigPath := filepath.Join(dir, "config.yml")
			if test.existing {
				fixture := newCommandImportFixture(t)
				configPath = fixture.agentConfigPath
				nebulaConfigPath = fixture.nebulaConfigPath
			}
			var stdout, stderr bytes.Buffer
			err := run(t.Context(), []string{
				"enroll", "--config", configPath, "--server", server.URL,
				"--token", test.token, "--data-dir", filepath.Dir(nebulaConfigPath),
				"--nebula-config-path", nebulaConfigPath,
			}, &stdout, &stderr)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
			if server.calls.Load() != 0 {
				t.Fatalf("network calls = %d, want 0", server.calls.Load())
			}
			if strings.Contains(stderr.String(), test.token) {
				t.Fatalf("stderr leaked token: %s", stderr.String())
			}
		})
	}
}

func TestReadBootstrapTokenSources(t *testing.T) {
	var stderr bytes.Buffer
	token, err := readBootstrapToken("nme_direct-secret", "", &stderr)
	if err != nil || token != "nme_direct-secret" {
		t.Fatalf("direct token = %q, %v", token, err)
	}
	if !strings.Contains(stderr.String(), "shell history") || strings.Contains(stderr.String(), token) {
		t.Fatalf("direct-token warning = %q", stderr.String())
	}

	path := filepath.Join(t.TempDir(), "bootstrap.token")
	if err := os.WriteFile(path, []byte("nmi_file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	token, err = readBootstrapToken("", path, &stderr)
	if err != nil || token != "nmi_file-secret" || stderr.Len() != 0 {
		t.Fatalf("file token = %q, %v; stderr=%q", token, err, stderr.String())
	}
	if _, err := readBootstrapToken("nme_one", path, &stderr); err == nil {
		t.Fatal("combined token sources accepted")
	}
}

type commandImportFixture struct {
	dir              string
	agentConfigPath  string
	nebulaConfigPath string
	caPath           string
	certPath         string
	keyPath          string
	signingKeyPath   string
	tokenFilePath    string
}

func newCommandImportFixture(t *testing.T) commandImportFixture {
	t.Helper()
	dir := t.TempDir()
	nebulaDir := filepath.Join(dir, "nebula-custom")
	if err := os.MkdirAll(nebulaDir, 0o750); err != nil {
		t.Fatal(err)
	}
	fixture := commandImportFixture{
		dir: dir, agentConfigPath: filepath.Join(dir, "agent", "agent.yml"),
		nebulaConfigPath: filepath.Join(nebulaDir, "existing.yml"), caPath: filepath.Join(nebulaDir, "root.pem"),
		certPath: filepath.Join(nebulaDir, "node.pem"), keyPath: filepath.Join(nebulaDir, "node.key"),
		signingKeyPath: filepath.Join(dir, "agent", "host.signing.key"), tokenFilePath: filepath.Join(dir, "import.token"),
	}
	caManager, err := pki.NewCA("command-import", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer caManager.Wipe()
	caPEM, err := caManager.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	hostCertificate, err := caManager.Sign(pki.SignRequest{
		Name: "command-host", PublicKey: publicKey,
		Networks: []netip.Prefix{netip.MustParsePrefix("10.90.0.10/16")}, Duration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, err := hostCertificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		fixture.caPath: caPEM, fixture.certPath: hostPEM,
		fixture.keyPath: cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, privateKey),
		fixture.nebulaConfigPath: []byte(fmt.Sprintf(
			"pki:\n  ca: %s\n  cert: %s\n  key: %s\nfirewall:\n  inbound: []\n  outbound: []\n",
			fixture.caPath, fixture.certPath, fixture.keyPath)),
		fixture.tokenFilePath: []byte("nmi_command-token\n"),
	}
	for path, contents := range files {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	clear(privateKey)
	return fixture
}

func (fixture commandImportFixture) args(serverURL string, yes bool) []string {
	args := []string{
		"enroll", "--config", fixture.agentConfigPath, "--server", serverURL,
		"--token-file", fixture.tokenFilePath, "--data-dir", filepath.Dir(fixture.nebulaConfigPath),
		"--nebula-config-path", fixture.nebulaConfigPath, "--signing-key-path", fixture.signingKeyPath,
	}
	if yes {
		args = append(args, "--yes")
	}
	return args
}

func (fixture commandImportFixture) readNebulaFiles(t *testing.T) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, path := range []string{fixture.caPath, fixture.certPath, fixture.keyPath, fixture.nebulaConfigPath} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = contents
	}
	return result
}

type commandImportServer struct {
	*httptest.Server
	calls           atomic.Int32
	imports         atomic.Int32
	proofFailures   atomic.Int32
	proofHash       string
	fingerprint     string
	polled          chan struct{}
	pollFingerprint atomic.Value
}

func newCommandImportServer(t *testing.T) *commandImportServer {
	t.Helper()
	server := &commandImportServer{polled: make(chan struct{}, 1)}
	server.Server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		server.calls.Add(1)
		var body struct {
			SigningPEM  string `json:"agent_signing_public_key_pem"`
			PayloadHash string `json:"payload_hash"`
			Proof       string `json:"proof"`
			Snapshot    struct {
				CertificatePEM string `json:"certificate_pem"`
			} `json:"snapshot"`
		}
		if request.Method == http.MethodPost {
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		switch request.URL.Path {
		case "/api/v1/agent/import/challenge":
			hostCertificate, _, err := cert.UnmarshalCertificateFromPEM([]byte(body.Snapshot.CertificatePEM))
			if err != nil {
				t.Error(err)
				return
			}
			server.fingerprint, err = hostCertificate.Fingerprint()
			if err != nil {
				t.Error(err)
				return
			}
			challenge, proofHash, err := importproof.Generate(rand.Reader, hostCertificate.PublicKey(), importproof.Binding{
				SessionID: "session-command", CertificateFingerprint: server.fingerprint,
				AgentSigningPublicKeyPEM: body.SigningPEM, PayloadHash: body.PayloadHash,
			})
			if err != nil {
				t.Error(err)
				return
			}
			server.proofHash = proofHash
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(map[string]any{
				"challenge_id": "challenge-command", "session_id": "session-command",
				"server_public_key": base64.RawURLEncoding.EncodeToString(challenge.ServerPublicKey),
				"server_nonce":      base64.RawURLEncoding.EncodeToString(challenge.Nonce), "expires_at": time.Now().Add(time.Minute),
			})
		case "/api/v1/agent/import":
			proof, err := base64.RawURLEncoding.DecodeString(body.Proof)
			if err != nil || len(proof) != sha256.Size || !importproof.VerifyHash(server.proofHash, proof) {
				server.proofFailures.Add(1)
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			server.imports.Add(1)
			response.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(response).Encode(map[string]any{
				"host_id": "command-host-id", "certificate_fingerprint": server.fingerprint,
				"status": "importing", "created": true,
			})
		case "/api/v1/agent/updates":
			server.pollFingerprint.Store(request.Header.Get("X-Nebula-Fingerprint"))
			select {
			case server.polled <- struct{}{}:
			default:
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"has_updates": false, "import_pending": true})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}
