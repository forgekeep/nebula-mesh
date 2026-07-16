package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/agent"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
)

type existingMeshHost struct {
	name, configPath, caPath, certPath, keyPath, signingPath string
	fingerprint, hostID                                      string
	originalHashes                                           map[string][32]byte
}

func TestE2EMeshImportPreservesKeysUntilAtomicFinalize(t *testing.T) {
	ts, st, _ := setupE2E(t)
	manager, err := pki.NewCA("imported-e2e-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Wipe()
	caPEM, err := manager.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	passphrase := []byte("integration import passphrase")
	encryptedKey, err := cert.EncryptAndMarshalSigningPrivateKey(
		cert.Curve_CURVE25519, manager.RawKey(), passphrase, cert.NewArgon2Parameters(64, 1, 1),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp := caImportCall(t, ts.URL, "imported-e2e-ca", caPEM, encryptedKey, passphrase)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("import CA: HTTP %d: %s", resp.StatusCode, readResponse(t, resp))
	}
	var importedCA models.CA
	decodeResponse(t, resp, &importedCA)
	if importedCA.Fingerprint == "" {
		t.Fatal("imported CA fingerprint is empty")
	}

	resp = apiCall(t, ts, http.MethodPost, "/api/v1/networks", map[string]any{
		"name": "imported-e2e-network", "cidrs": []string{"10.77.0.0/16"}, "ca_id": importedCA.ID,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create import Network: HTTP %d: %s", resp.StatusCode, readResponse(t, resp))
	}
	var network models.Network
	decodeResponse(t, resp, &network)

	expectedHosts := 2
	resp = apiCall(t, ts, http.MethodPost, "/api/v1/mesh-imports", map[string]any{
		"network_id": network.ID, "ca_id": importedCA.ID, "expected_hosts": expectedHosts,
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create mesh import: HTTP %d: %s", resp.StatusCode, readResponse(t, resp))
	}
	var session struct {
		MeshImport models.MeshImport `json:"mesh_import"`
		Token      string            `json:"token"`
	}
	decodeResponse(t, resp, &session)
	if !strings.HasPrefix(session.Token, "nmi_") {
		t.Fatalf("import token = %q", session.Token)
	}

	root := t.TempDir()
	lighthouse := createExistingMeshHost(t, manager, caPEM, root, "lighthouse", "10.77.0.1/16", true)
	peer := createExistingMeshHost(t, manager, caPEM, root, "peer", "10.77.0.2/16", false)
	for _, host := range []*existingMeshHost{lighthouse, peer} {
		discovery, err := agent.DiscoverExisting(host.configPath)
		if err != nil || discovery.State != agent.DiscoveryComplete {
			t.Fatalf("discover %s: state=%v issues=%v err=%v", host.name, discovery.State, discovery.Issues, err)
		}
		result, err := agent.ImportExisting(context.Background(), ts.URL, session.Token, host.signingPath, discovery)
		if err != nil {
			t.Fatalf("import %s: %v", host.name, err)
		}
		host.hostID, host.fingerprint = result.HostID, result.Fingerprint
		assertExistingHostFilesUnchanged(t, host)
	}

	// Retry one complete submission with the stable signing key. The server
	// returns the existing Host and leaves the session revision unchanged.
	retryDiscovery, err := agent.DiscoverExisting(peer.configPath)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := agent.ImportExisting(context.Background(), ts.URL, session.Token, peer.signingPath, retryDiscovery)
	if err != nil || retry.Created || retry.HostID != peer.hostID {
		t.Fatalf("idempotent import retry = %#v, %v", retry, err)
	}

	for _, host := range []*existingMeshHost{lighthouse, peer} {
		signingPrivate := readAgentSigningPrivateKey(t, host.signingPath)
		poll := signedGetUpdates(t, ts, host.fingerprint, signingPrivate)
		if poll.StatusCode != http.StatusOK {
			t.Fatalf("pending poll %s: HTTP %d: %s", host.name, poll.StatusCode, readResponse(t, poll))
		}
		var updates agent.UpdatesResponse
		decodeResponse(t, poll, &updates)
		if !updates.ImportPending || updates.HasUpdates {
			t.Fatalf("pending poll %s = %#v", host.name, updates)
		}
		assertExistingHostFilesUnchanged(t, host)
	}

	resp = apiCall(t, ts, http.MethodGet, "/api/v1/mesh-imports/"+session.MeshImport.ID, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mesh import preview: HTTP %d: %s", resp.StatusCode, readResponse(t, resp))
	}
	var detail struct {
		MeshImport models.MeshImport `json:"mesh_import"`
		HostCount  int               `json:"host_count"`
		Report     struct {
			Blockers []any `json:"blockers"`
			Warnings []any `json:"warnings"`
		} `json:"report"`
	}
	decodeResponse(t, resp, &detail)
	if detail.HostCount != 2 || len(detail.Report.Blockers) != 0 || len(detail.Report.Warnings) != 0 {
		t.Fatalf("mesh import preview = %#v", detail)
	}
	resp = apiCall(t, ts, http.MethodPost, "/api/v1/mesh-imports/"+session.MeshImport.ID+"/finalize", map[string]any{
		"revision": detail.MeshImport.Revision, "inventory_complete": true, "acknowledged_warnings": []string{},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize mesh import: HTTP %d: %s", resp.StatusCode, readResponse(t, resp))
	}
	_ = resp.Body.Close()

	for _, host := range []*existingMeshHost{lighthouse, peer} {
		stored, err := st.GetHost(context.Background(), host.hostID)
		if err != nil || stored.Status != models.HostStatusEnrolled {
			t.Fatalf("finalized host %s = %#v, %v", host.name, stored, err)
		}
		poller, err := agent.NewPoller(agent.PollerConfig{
			ServerURL: ts.URL, Fingerprint: host.fingerprint, SigningKeyPath: host.signingPath,
			DataDir: filepath.Dir(host.certPath), NebulaConfigPath: host.configPath,
			NebulaCAPath: host.caPath, NebulaCertPath: host.certPath, NebulaKeyPath: host.keyPath,
			ImportSessionID: session.MeshImport.ID, Interval: time.Second,
		}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if err != nil {
			t.Fatal(err)
		}
		if err := poller.PollOnce(context.Background()); err != nil {
			t.Fatalf("managed poll %s: %v", host.name, err)
		}
		assertHostPrivateKeyUnchanged(t, host)
		configBytes, err := os.ReadFile(host.configPath)
		if err != nil {
			t.Fatal(err)
		}
		configText := string(configBytes)
		expectedValues := []string{host.caPath, host.certPath, host.keyPath}
		if host == lighthouse {
			expectedValues = append(expectedValues, "am_lighthouse: true")
		} else {
			expectedValues = append(expectedValues, "10.77.0.1", "203.0.113.10:4242")
		}
		for _, expected := range expectedValues {
			if !strings.Contains(configText, expected) {
				t.Fatalf("managed config %s missing %q:\n%s", host.name, expected, configText)
			}
		}
		backup := host.configPath + ".pre-nebula-mesh." + session.MeshImport.ID
		if info, err := os.Stat(backup); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("backup %s: info=%v err=%v", host.name, info, err)
		}
	}
}

func caImportCall(t *testing.T, serverURL, name string, certificatePEM, privateKeyPEM, passphrase []byte) *http.Response {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, field := range []struct {
		name  string
		value []byte
	}{
		{name: "name", value: []byte(name)},
		{name: "certificate", value: certificatePEM},
		{name: "private_key", value: privateKeyPEM},
		{name: "passphrase", value: passphrase},
	} {
		part, err := writer.CreateFormField(field.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(field.value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/cas/import", bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func createExistingMeshHost(t *testing.T, manager *pki.CAManager, caPEM []byte, root, name, overlay string, lighthouse bool) *existingMeshHost {
	t.Helper()
	directory := filepath.Join(root, name)
	if err := os.MkdirAll(directory, 0o700); err != nil {
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
	hostCertificate, err := manager.Sign(pki.SignRequest{
		Name: name, PublicKey: publicKey, Networks: []netip.Prefix{netip.MustParsePrefix(overlay)},
		Groups: []string{"prod"}, Duration: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := hostCertificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	host := &existingMeshHost{
		name: name, configPath: filepath.Join(directory, "nebula.yml"), caPath: filepath.Join(directory, "root.pem"),
		certPath: filepath.Join(directory, "identity.crt"), keyPath: filepath.Join(directory, "identity.key"),
		signingPath: filepath.Join(directory, "agent.signing.key"), originalHashes: make(map[string][32]byte),
	}
	files := map[string]struct {
		contents []byte
		mode     os.FileMode
	}{
		host.caPath: {caPEM, 0o644}, host.certPath: {certificatePEM, 0o644},
		host.keyPath: {cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, privateKey), 0o600},
	}
	for path, file := range files {
		if err := os.WriteFile(path, file.contents, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	amLighthouse := "false"
	if lighthouse {
		amLighthouse = "true"
	}
	config := fmt.Sprintf(`pki:
  ca: %q
  cert: %q
  key: %q
static_host_map:
  "10.77.0.1": ["203.0.113.10:4242"]
lighthouse:
  am_lighthouse: %s
  hosts: ["10.77.0.1"]
listen:
  host: 0.0.0.0
  port: 4242
firewall:
  inbound:
    - {port: "22", proto: tcp, group: prod}
  outbound:
    - {port: any, proto: any, group: any}
`, host.caPath, host.certPath, host.keyPath, amLighthouse)
	if err := os.WriteFile(host.configPath, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{host.configPath, host.caPath, host.certPath, host.keyPath} {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		host.originalHashes[path] = sha256.Sum256(contents)
	}
	return host
}

func assertExistingHostFilesUnchanged(t *testing.T, host *existingMeshHost) {
	t.Helper()
	for path, expected := range host.originalHashes {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(contents) != expected {
			t.Fatalf("existing file changed before finalize: %s", path)
		}
	}
}

func assertHostPrivateKeyUnchanged(t *testing.T, host *existingMeshHost) {
	t.Helper()
	contents, err := os.ReadFile(host.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(contents) != host.originalHashes[host.keyPath] {
		t.Fatalf("host private key changed: %s", host.keyPath)
	}
}

func readAgentSigningPrivateKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(contents)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Bytes) != ed25519.PrivateKeySize {
		t.Fatalf("invalid signing key at %s", path)
	}
	return ed25519.PrivateKey(block.Bytes)
}

func decodeResponse(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func readResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	contents, _ := io.ReadAll(response.Body)
	return string(contents)
}
