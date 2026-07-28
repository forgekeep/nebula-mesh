package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

func TestPollerImportedConfigCreatesOwnerOnlyBackupOnce(t *testing.T) {
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	configPath := filepath.Join(dir, "custom", "node.yml")
	caPath := filepath.Join(dir, "pki", "root.pem")
	certPath := filepath.Join(dir, "pki", "node.pem")
	keyPath := filepath.Join(dir, "pki", "node.key")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o750); err != nil {
		t.Fatal(err)
	}
	original := "pki:\n  ca: " + caPath + "\n  cert: " + certPath + "\n  key: " + keyPath + "\nsshd:\n  host_key: INLINE-SECRET-CANARY\n"
	if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	candidate := "pki:\n  ca: " + caPath + "\n  cert: " + certPath + "\n  key: " + keyPath + "\nfirewall:\n  inbound: []\n  outbound: []\n"
	server := updateConfigServer(t, candidate)
	p := newTestPoller(t, PollerConfig{
		ServerURL: server.URL, Fingerprint: "fp", DataDir: dir, SigningKeyPath: filepath.Join(dir, "host.signing.key"),
		NebulaConfigPath: configPath, NebulaCAPath: caPath, NebulaCertPath: certPath, NebulaKeyPath: keyPath,
		ImportSessionID: "session-safe", Interval: time.Hour,
	})
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	backupPath := configPath + ".pre-nebula-mesh.session-safe"
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(backup) != original {
		t.Fatalf("backup content changed: %q", backup)
	}
	info, err := os.Stat(backupPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode=%v err=%v", info.Mode(), err)
	}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	backupAgain, _ := os.ReadFile(backupPath)
	if string(backupAgain) != original {
		t.Fatal("second apply overwrote deterministic backup")
	}
}

func TestPollerRejectsUnsafeCandidateBeforeWriteOrSignal(t *testing.T) {
	tests := []struct {
		name      string
		candidate string
		backup    string
	}{
		{name: "path mismatch", candidate: "pki:\n  ca: /wrong/ca.crt\n  cert: %CERT%\n  key: %KEY%\n"},
		{name: "invalid yaml", candidate: "pki: [unterminated"},
		{name: "backup symlink", candidate: "pki:\n  ca: %CA%\n  cert: %CERT%\n  key: %KEY%\n", backup: "symlink"},
		{name: "backup directory", candidate: "pki:\n  ca: %CA%\n  cert: %CERT%\n  key: %KEY%\n", backup: "directory"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			seedSigningKeyAt(t, dir)
			configPath := filepath.Join(dir, "node.yml")
			caPath, certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "node.crt"), filepath.Join(dir, "node.key")
			original := "pki:\n  ca: " + caPath + "\n  cert: " + certPath + "\n  key: " + keyPath + "\n"
			if err := os.WriteFile(configPath, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			candidate := strings.NewReplacer("%CA%", caPath, "%CERT%", certPath, "%KEY%", keyPath).Replace(test.candidate)
			backupPath := configPath + ".pre-nebula-mesh.session"
			switch test.backup {
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "attacker"), backupPath); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(backupPath, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			server := updateConfigServer(t, candidate)
			p := newTestPoller(t, PollerConfig{
				ServerURL: server.URL, Fingerprint: "fp", DataDir: dir, SigningKeyPath: filepath.Join(dir, "host.signing.key"),
				NebulaConfigPath: configPath, NebulaCAPath: caPath, NebulaCertPath: certPath, NebulaKeyPath: keyPath,
				ImportSessionID: "session", Interval: time.Hour,
			})
			var signals atomic.Int32
			p.signalFunc = func(context.Context) error { signals.Add(1); return nil }
			if err := p.PollOnce(context.Background()); err == nil {
				t.Fatal("unsafe candidate accepted")
			}
			got, _ := os.ReadFile(configPath)
			if string(got) != original || signals.Load() != 0 {
				t.Fatalf("unsafe apply changed state: config=%q signals=%d", got, signals.Load())
			}
		})
	}
}

func TestPollerRenewalUsesExplicitPathAndSwitchesFingerprint(t *testing.T) {
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	certificatePEM := validPollerHostCertificate(t)
	certificate, _, err := cert.UnmarshalCertificateFromPEM([]byte(certificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	wantFingerprint, err := certificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var secondFingerprint atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if calls.Add(1) == 1 {
			_ = json.NewEncoder(response).Encode(UpdatesResponse{HasUpdates: true, CertificatePEM: &certificatePEM})
			return
		}
		secondFingerprint.Store(request.Header.Get("X-Nebula-Fingerprint"))
		_ = json.NewEncoder(response).Encode(UpdatesResponse{HasUpdates: false})
	}))
	t.Cleanup(server.Close)
	explicitCertPath := filepath.Join(dir, "custom-pki", "node.crt")
	if err := os.MkdirAll(filepath.Dir(explicitCertPath), 0o750); err != nil {
		t.Fatal(err)
	}
	p := newTestPoller(t, PollerConfig{
		ServerURL: server.URL, Fingerprint: "old-fingerprint", DataDir: dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"), NebulaCertPath: explicitCertPath, Interval: time.Hour,
	})
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if secondFingerprint.Load() != wantFingerprint {
		t.Fatalf("second poll fingerprint = %v, want %s", secondFingerprint.Load(), wantFingerprint)
	}
	if _, err := os.Stat(explicitCertPath); err != nil {
		t.Fatalf("certificate not written to explicit path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "host.crt")); !os.IsNotExist(err) {
		t.Fatalf("legacy cert path was written: %v", err)
	}
}

func TestPollerAcknowledgesAppliedConfigWithRenewedFingerprint(t *testing.T) {
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	caPath, certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	configPath := filepath.Join(dir, "config.yml")
	rendered := "pki:\n  ca: " + caPath + "\n  cert: " + certPath + "\n  key: " + keyPath + "\n"
	certificatePEM := validPollerHostCertificate(t)
	certificate, _, _ := cert.UnmarshalCertificateFromPEM([]byte(certificatePEM))
	wantFingerprint, _ := certificate.Fingerprint()
	var ackFingerprint atomic.Value
	var ackCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/agent/updates" {
			_ = json.NewEncoder(response).Encode(UpdatesResponse{
				HasUpdates: true, CertificatePEM: &certificatePEM, ConfigYAML: &rendered, ConfigVersion: 7,
			})
			return
		}
		if request.URL.Path == "/api/v1/agent/config-ack/7" {
			ackCalls.Add(1)
			ackFingerprint.Store(request.Header.Get("X-Nebula-Fingerprint"))
			_ = json.NewEncoder(response).Encode(map[string]int{"config_version": 7})
			return
		}
		response.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	p := newTestPoller(t, PollerConfig{
		ServerURL: server.URL, Fingerprint: "old-fingerprint", DataDir: dir,
		SigningKeyPath: filepath.Join(dir, "host.signing.key"), NebulaConfigPath: configPath,
		NebulaCAPath: caPath, NebulaCertPath: certPath, NebulaKeyPath: keyPath, Interval: time.Hour,
	})
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ackCalls.Load() != 1 || ackFingerprint.Load() != wantFingerprint {
		t.Fatalf("ack calls=%d fingerprint=%v, want %s", ackCalls.Load(), ackFingerprint.Load(), wantFingerprint)
	}
}

func TestPollerDoesNotAckWhenConfiguredReloadSignalFails(t *testing.T) {
	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	caPath, certPath, keyPath := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key")
	rendered := "pki:\n  ca: " + caPath + "\n  cert: " + certPath + "\n  key: " + keyPath + "\n"
	var ackCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/agent/updates" {
			_ = json.NewEncoder(response).Encode(UpdatesResponse{HasUpdates: true, ConfigYAML: &rendered, ConfigVersion: 9})
			return
		}
		ackCalls.Add(1)
		response.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	p := newTestPoller(t, PollerConfig{
		ServerURL: server.URL, Fingerprint: "fingerprint", DataDir: dir, PIDFile: filepath.Join(dir, "nebula.pid"),
		SigningKeyPath: filepath.Join(dir, "host.signing.key"), NebulaCAPath: caPath,
		NebulaCertPath: certPath, NebulaKeyPath: keyPath, Interval: time.Hour,
	})
	p.signalFunc = func(context.Context) error { return errors.New("signal delivery failed") }
	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ackCalls.Load() != 0 {
		t.Fatalf("ack sent after signal failure: %d", ackCalls.Load())
	}
}

func updateConfigServer(t *testing.T, rendered string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(UpdatesResponse{HasUpdates: true, ConfigYAML: &rendered})
	}))
	t.Cleanup(server.Close)
	return server
}
