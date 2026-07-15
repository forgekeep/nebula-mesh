package simtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	agentclient "github.com/forgekeep/nebula-mesh/internal/agent"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
)

// TestSim_MeshImportConvergesOnlyAfterFinalize pins the fleet transition:
// an imported identity may authenticate while collecting, but receives no
// managed state until the whole session is finalized atomically.
func TestSim_MeshImportConvergesOnlyAfterFinalize(t *testing.T) {
	h := New(t)
	networkID := h.CreateNetwork("import-sim", "10.88.0.0/16")
	expectedHosts := 1
	var created struct {
		MeshImport models.MeshImport `json:"mesh_import"`
		Token      string            `json:"token"`
	}
	if code := h.API(http.MethodPost, "/api/v1/mesh-imports", map[string]any{
		"network_id": networkID, "ca_id": h.CA.ID, "expected_hosts": expectedHosts,
	}, &created); code != http.StatusCreated {
		t.Fatalf("create import session: HTTP %d", code)
	}

	configPath, keyHash := writeSimExistingInstallation(t, h)
	signingPath := filepath.Join(filepath.Dir(configPath), "agent-signing.key")
	discovery, err := agentclient.DiscoverExisting(configPath)
	if err != nil || discovery.State != agentclient.DiscoveryComplete {
		t.Fatalf("discover existing installation: state=%s issues=%v err=%v", discovery.State, discovery.Issues, err)
	}
	imported, err := agentclient.ImportExisting(context.Background(), h.Server.URL, created.Token, signingPath, discovery)
	if err != nil {
		t.Fatalf("import existing installation: %v", err)
	}
	virtualAgent := &Agent{
		HostID: imported.HostID, Name: "existing-sim-host", Fingerprint: imported.Fingerprint,
		signingPriv: readSimSigningKey(t, signingPath),
	}
	if pending := virtualAgent.Poll(h); !pending.ImportPending || pending.HasUpdates || pending.ConfigYAML != nil {
		t.Fatalf("collecting poll exposed managed state: %#v", pending)
	}

	var detail struct {
		MeshImport models.MeshImport `json:"mesh_import"`
		Report     struct {
			Blockers []any `json:"blockers"`
			Warnings []any `json:"warnings"`
		} `json:"report"`
	}
	if code := h.API(http.MethodGet, "/api/v1/mesh-imports/"+created.MeshImport.ID, nil, &detail); code != http.StatusOK {
		t.Fatalf("preview import: HTTP %d", code)
	}
	if len(detail.Report.Blockers) != 0 || len(detail.Report.Warnings) != 0 {
		t.Fatalf("unexpected preview issues: %#v", detail.Report)
	}
	if code := h.API(http.MethodPost, "/api/v1/mesh-imports/"+created.MeshImport.ID+"/finalize", map[string]any{
		"revision": detail.MeshImport.Revision, "inventory_complete": true, "acknowledged_warnings": []string{},
	}, nil); code != http.StatusOK {
		t.Fatalf("finalize import: HTTP %d", code)
	}

	update := virtualAgent.Poll(h)
	if update.ImportPending || update.ConfigYAML == nil || update.ConfigVersion <= 0 {
		t.Fatalf("finalized host did not receive managed config: %#v", update)
	}
	if status := virtualAgent.AckConfig(h, update.ConfigVersion); status != http.StatusOK {
		t.Fatalf("ack finalized config: HTTP %d", status)
	}
	if converged := virtualAgent.Poll(h); converged.ConfigYAML != nil || converged.ImportPending {
		t.Fatalf("finalized host did not converge: %#v", converged)
	}
	keyBytes, err := os.ReadFile(filepath.Join(filepath.Dir(configPath), "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(keyBytes) != keyHash {
		t.Fatal("existing host private key changed during import")
	}
}

func writeSimExistingInstallation(t *testing.T, h *Harness) (string, [32]byte) {
	t.Helper()
	manager, err := pki.NewCAResolver(h.Store, h.master).LoadByID(context.Background(), h.CA.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Wipe()
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	hostCertificate, err := manager.Sign(pki.SignRequest{
		Name: "existing-sim-host", PublicKey: publicKey,
		Networks: []netip.Prefix{netip.MustParsePrefix("10.88.0.10/16")}, Duration: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := hostCertificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.crt")
	certPath := filepath.Join(directory, "host.crt")
	keyPath := filepath.Join(directory, "host.key")
	configPath := filepath.Join(directory, "config.yml")
	keyPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, privateKey)
	for path, contents := range map[string][]byte{caPath: []byte(h.CA.CertPEM), certPath: certificatePEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	configuration := fmt.Sprintf("pki:\n  ca: %q\n  cert: %q\n  key: %q\nlighthouse:\n  am_lighthouse: false\n  hosts: []\n", caPath, certPath, keyPath)
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, sha256.Sum256(keyPEM)
}

func readSimSigningKey(t *testing.T, path string) ed25519.PrivateKey {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(contents)
	if block == nil || len(rest) != 0 || len(block.Bytes) != ed25519.PrivateKeySize {
		t.Fatalf("invalid agent signing key at %s", path)
	}
	return ed25519.PrivateKey(block.Bytes)
}
