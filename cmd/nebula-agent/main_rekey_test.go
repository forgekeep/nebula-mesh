package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	meshagent "github.com/forgekeep/nebula-mesh/internal/agent"
	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
)

func TestRekeyPreservesImportedNebulaPaths(t *testing.T) {
	fixture := newCommandImportFixture(t)
	dataDir := filepath.Join(fixture.dir, "managed-defaults")
	if err := os.MkdirAll(filepath.Dir(fixture.signingKeyPath), 0o750); err != nil {
		t.Fatal(err)
	}
	_, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.signingKeyPath, pem.EncodeToMemory(&pem.Block{
		Type: meshagent.SigningPrivateKeyPEMType, Bytes: signingPrivate,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	clear(signingPrivate)

	oldFingerprint, err := meshagent.ReadCertFingerprintAt(fixture.certPath)
	if err != nil {
		t.Fatal(err)
	}
	caManager, err := pki.NewCA("rekey-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer caManager.Wipe()
	caPEM, err := caManager.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}

	profileCh := make(chan models.AgentProfile, 1)
	secondFingerprintCh := make(chan string, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var updateCalls int
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/agent/updates":
			updateCalls++
			if updateCalls == 1 {
				_ = json.NewEncoder(response).Encode(map[string]any{
					"has_updates": true, "rekey_required": true,
					"enrollment_token": "nme_rekey-token", "blocklist": []string{},
				})
				return
			}
			secondFingerprintCh <- request.Header.Get("X-Nebula-Fingerprint")
			cancel()
			_ = json.NewEncoder(response).Encode(map[string]any{"has_updates": false, "blocklist": []string{}})
		case "/api/v1/enroll":
			var body struct {
				PublicKeyPEM string              `json:"public_key_pem"`
				Profile      models.AgentProfile `json:"profile"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			publicKey, _, _, err := cert.UnmarshalPublicKeyFromPEM([]byte(body.PublicKeyPEM))
			if err != nil {
				t.Error(err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			hostCertificate, err := caManager.Sign(pki.SignRequest{
				Name: "rekeyed-host", PublicKey: publicKey,
				Networks: []netip.Prefix{netip.MustParsePrefix("10.90.0.10/16")}, Duration: time.Hour,
			})
			if err != nil {
				t.Error(err)
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			certificatePEM, err := hostCertificate.MarshalPEM()
			if err != nil {
				t.Error(err)
				response.WriteHeader(http.StatusInternalServerError)
				return
			}
			profileCh <- body.Profile
			_ = json.NewEncoder(response).Encode(meshagent.EnrollResponse{
				CertificatePEM: string(certificatePEM), CACertificatePEM: string(caPEM),
				ConfigYAML: "pki:\n  ca: " + fixture.caPath + "\n  cert: " + fixture.certPath + "\n  key: " + fixture.keyPath + "\n",
			})
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	cfg := &config.AgentConfig{
		ServerURL: server.URL, DataDir: dataDir, SigningKeyPath: fixture.signingKeyPath,
		PollInterval: time.Hour, NebulaConfigPath: fixture.nebulaConfigPath,
		NebulaCAPath: fixture.caPath, NebulaCertPath: fixture.certPath, NebulaKeyPath: fixture.keyPath,
	}
	done := make(chan error, 1)
	go func() { done <- startPoller(ctx, cfg, slog.Default()) }()
	if err := <-done; err != nil {
		t.Fatalf("startPoller: %v", err)
	}

	profile := <-profileCh
	wantProfile := models.AgentProfile{
		NebulaConfigPath: fixture.nebulaConfigPath, NebulaCAPath: fixture.caPath,
		NebulaCertPath: fixture.certPath, NebulaKeyPath: fixture.keyPath, ConfigAckV1: true,
	}
	if profile != wantProfile {
		t.Fatalf("rekey profile = %#v, want %#v", profile, wantProfile)
	}
	newFingerprint, err := meshagent.ReadCertFingerprintAt(fixture.certPath)
	if err != nil {
		t.Fatal(err)
	}
	if newFingerprint == oldFingerprint {
		t.Fatal("custom certificate was not replaced")
	}
	if secondFingerprint := <-secondFingerprintCh; secondFingerprint != newFingerprint {
		t.Fatalf("second poll fingerprint = %q, want %q", secondFingerprint, newFingerprint)
	}
	for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); !os.IsNotExist(err) {
			t.Fatalf("unexpected default PKI file %s: %v", name, err)
		}
	}
}
