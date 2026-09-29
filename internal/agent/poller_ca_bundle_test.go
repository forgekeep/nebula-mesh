package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/pki"
)

func testPollerCAPEM(t *testing.T, name string) string {
	t.Helper()
	manager, err := pki.NewCA(name, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(manager.Wipe)
	pem, err := manager.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	return string(pem)
}

func TestPollerAppliesRotationCABundleAndBlocklistConfig(t *testing.T) {
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	caPath := filepath.Join(dir, "ca.crt")
	configPath := filepath.Join(dir, "config.yml")
	currentCA := testPollerCAPEM(t, "current")
	successorCA := testPollerCAPEM(t, "successor")
	bundle := currentCA + "\n" + successorCA
	blockedFingerprint := strings.Repeat("a", 64)
	configYAML := fmt.Sprintf("pki:\n  ca: %s\n  cert: %s\n  key: %s\n  blocklist:\n    - %s\n",
		caPath, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), blockedFingerprint)
	var acknowledgements atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/agent/updates":
			_ = json.NewEncoder(response).Encode(UpdatesResponse{
				HasUpdates: true, CACertPEM: &bundle, ConfigYAML: &configYAML, ConfigVersion: 7,
			})
		case "/api/v1/agent/config-ack/7":
			acknowledgements.Add(1)
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	poller := newTestPoller(t, PollerConfig{
		ServerURL: server.URL, Fingerprint: "fingerprint", DataDir: dir,
		NebulaCAPath: caPath, NebulaConfigPath: configPath, Interval: time.Hour,
	})
	var reloads atomic.Int32
	poller.signalFunc = func(context.Context) error { reloads.Add(1); return nil }

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatalf("poll with rotation bundle: %v", err)
	}
	gotCA, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCA) != bundle {
		t.Fatal("CA file does not contain both rotation roots")
	}
	pool, err := cert.NewCAPoolFromPEM(gotCA)
	if err != nil {
		t.Fatalf("Nebula CA pool could not load the bundle: %v", err)
	}
	if len(pool.CAs) != 2 {
		t.Fatalf("Nebula CA pool loaded %d roots, want 2", len(pool.CAs))
	}
	gotConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotConfig) != configYAML {
		t.Fatalf("blocklist config was not applied: %q", gotConfig)
	}
	if reloads.Load() != 1 || acknowledgements.Load() != 1 {
		t.Fatalf("reloads=%d acknowledgements=%d, want one each", reloads.Load(), acknowledgements.Load())
	}
}

// SEC-PERSIST-001: a rejected CA bundle must preserve the last applied CA and
// configuration, and must not acknowledge a configuration it did not apply.
func TestPollerRejectsInvalidRotationCABundleBeforeWriting(t *testing.T) {
	currentCA := testPollerCAPEM(t, "current")
	successorCA := testPollerCAPEM(t, "successor")
	otherCA := testPollerCAPEM(t, "third")
	hostCert := validPollerHostCertificate(t)
	cases := []struct {
		name   string
		bundle string
	}{
		{name: "host cert as successor", bundle: currentCA + "\n" + hostCert},
		{name: "truncated successor", bundle: currentCA + "\n-----BEGIN NEBULA CERTIFICATE-----\n"},
		{name: "trailing non-PEM data", bundle: currentCA + "\n" + successorCA + "\ntrailing data"},
		{name: "third CA", bundle: currentCA + "\n" + successorCA + "\n" + otherCA},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			seedSigningKeyAt(t, dir)
			caPath := filepath.Join(dir, "ca.crt")
			certPath := filepath.Join(dir, "host.crt")
			configPath := filepath.Join(dir, "config.yml")
			oldCA := []byte("old CA")
			oldCert := []byte("old host certificate")
			oldConfig := []byte("old config")
			if err := os.WriteFile(caPath, oldCA, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, oldConfig, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(certPath, oldCert, 0o644); err != nil {
				t.Fatal(err)
			}
			configYAML := fmt.Sprintf("pki:\n  ca: %s\n  cert: %s\n  key: %s\n",
				caPath, certPath, filepath.Join(dir, "host.key"))
			var acknowledgements atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/api/v1/agent/updates" {
					_ = json.NewEncoder(response).Encode(UpdatesResponse{
						HasUpdates: true, CertificatePEM: &hostCert, CACertPEM: &test.bundle,
						ConfigYAML: &configYAML, ConfigVersion: 7,
					})
					return
				}
				acknowledgements.Add(1)
				response.WriteHeader(http.StatusNoContent)
			}))
			t.Cleanup(server.Close)
			poller := newTestPoller(t, PollerConfig{
				ServerURL: server.URL, Fingerprint: "fingerprint", DataDir: dir,
				NebulaCAPath: caPath, NebulaConfigPath: configPath, Interval: time.Hour,
			})
			var reloads atomic.Int32
			poller.signalFunc = func(context.Context) error { reloads.Add(1); return nil }
			if err := poller.PollOnce(context.Background()); err == nil {
				t.Fatal("invalid CA bundle was accepted")
			}
			gotCA, err := os.ReadFile(caPath)
			if err != nil {
				t.Fatal(err)
			}
			gotConfig, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			gotCert, err := os.ReadFile(certPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(gotCA) != string(oldCA) || string(gotCert) != string(oldCert) || string(gotConfig) != string(oldConfig) ||
				reloads.Load() != 0 || acknowledgements.Load() != 0 {
				t.Fatalf("invalid bundle changed state: CA=%q cert=%q config=%q reloads=%d acks=%d",
					gotCA, gotCert, gotConfig, reloads.Load(), acknowledgements.Load())
			}
		})
	}
}
