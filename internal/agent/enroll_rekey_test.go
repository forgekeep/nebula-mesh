package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestReenrollUsesProfilePaths(t *testing.T) {
	root := t.TempDir()
	profile := models.AgentProfile{
		NebulaConfigPath: filepath.Join(root, "config", "nebula.yml"),
		NebulaCAPath:     filepath.Join(root, "pki", "root.pem"),
		NebulaCertPath:   filepath.Join(root, "pki", "node.pem"),
		NebulaKeyPath:    filepath.Join(root, "secret", "node.key"),
		ConfigAckV1:      true,
	}
	signingKeyPath := filepath.Join(root, "agent", "signing.key")
	var submitted models.AgentProfile
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var body struct {
			Profile models.AgentProfile `json:"profile"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		submitted = body.Profile
		_ = json.NewEncoder(response).Encode(EnrollResponse{
			CertificatePEM: "certificate", CACertificatePEM: "ca", ConfigYAML: "config",
		})
	}))
	t.Cleanup(server.Close)

	err := Reenroll(t.Context(), server.URL, "token", ReenrollOptions{
		DataDir: t.TempDir(), SigningKeyPath: signingKeyPath, Profile: profile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if submitted != profile {
		t.Fatalf("submitted profile = %#v, want %#v", submitted, profile)
	}
	for path, want := range map[string]string{
		profile.NebulaConfigPath: "config", profile.NebulaCAPath: "ca",
		profile.NebulaCertPath: "certificate",
	} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != want {
			t.Fatalf("file %s = %q, %v; want %q", path, contents, err, want)
		}
	}
	for _, path := range []string{profile.NebulaKeyPath, signingKeyPath} {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("generated key %s: info=%v err=%v", path, info, err)
		}
	}
}

func TestReenrollReloadsAfterWritesBeforeAck(t *testing.T) {
	root := t.TempDir()
	profile := models.AgentProfile{
		NebulaConfigPath: filepath.Join(root, "nebula.yml"),
		NebulaCAPath:     filepath.Join(root, "root.pem"),
		NebulaCertPath:   filepath.Join(root, "node.pem"),
		NebulaKeyPath:    filepath.Join(root, "node.key"),
		ConfigAckV1:      true,
	}
	certificatePEM := validPollerHostCertificate(t)
	var acknowledgements atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1/enroll":
			_ = json.NewEncoder(response).Encode(EnrollResponse{
				CertificatePEM: certificatePEM, CACertificatePEM: "ca", ConfigYAML: "config", ConfigVersion: 7,
			})
		case "/api/v1/agent/config-ack/7":
			acknowledgements.Add(1)
			response.WriteHeader(http.StatusNoContent)
		default:
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	reloaded := false
	err := reenrollWithSignal(t.Context(), server.URL, "token", ReenrollOptions{
		DataDir: t.TempDir(), SigningKeyPath: filepath.Join(root, "signing.key"),
		PIDFile: filepath.Join(root, "nebula.pid"), Profile: profile,
	}, func(pidFile string) error {
		if pidFile == "" {
			t.Fatal("reload called without PID file")
		}
		for _, path := range []string{profile.NebulaConfigPath, profile.NebulaCAPath, profile.NebulaCertPath, profile.NebulaKeyPath} {
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("reload before write of %s: %v", path, err)
			}
		}
		if acknowledgements.Load() != 0 {
			t.Fatal("config acknowledged before reload")
		}
		reloaded = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded || acknowledgements.Load() != 1 {
		t.Fatalf("reloaded=%v acknowledgements=%d", reloaded, acknowledgements.Load())
	}
}

func TestReenrollReloadFailureSuppressesAck(t *testing.T) {
	root := t.TempDir()
	profile := models.AgentProfile{
		NebulaConfigPath: filepath.Join(root, "nebula.yml"), NebulaCAPath: filepath.Join(root, "root.pem"),
		NebulaCertPath: filepath.Join(root, "node.pem"), NebulaKeyPath: filepath.Join(root, "node.key"), ConfigAckV1: true,
	}
	var acknowledgements atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/enroll" {
			_ = json.NewEncoder(response).Encode(EnrollResponse{
				CertificatePEM: validPollerHostCertificate(t), CACertificatePEM: "ca", ConfigYAML: "config", ConfigVersion: 3,
			})
			return
		}
		acknowledgements.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	wantErr := errors.New("reload failed")
	err := reenrollWithSignal(t.Context(), server.URL, "token", ReenrollOptions{
		DataDir: t.TempDir(), SigningKeyPath: filepath.Join(root, "signing.key"),
		PIDFile: filepath.Join(root, "nebula.pid"), Profile: profile,
	}, func(string) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if acknowledgements.Load() != 0 {
		t.Fatalf("acknowledgements = %d, want 0", acknowledgements.Load())
	}
}

func TestReenrollWithoutPIDFileSkipsReloadAndAcknowledges(t *testing.T) {
	root := t.TempDir()
	profile := models.AgentProfile{
		NebulaConfigPath: filepath.Join(root, "nebula.yml"), NebulaCAPath: filepath.Join(root, "root.pem"),
		NebulaCertPath: filepath.Join(root, "node.pem"), NebulaKeyPath: filepath.Join(root, "node.key"), ConfigAckV1: true,
	}
	var acknowledgements atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1/enroll" {
			_ = json.NewEncoder(response).Encode(EnrollResponse{
				CertificatePEM: validPollerHostCertificate(t), CACertificatePEM: "ca", ConfigYAML: "config", ConfigVersion: 2,
			})
			return
		}
		acknowledgements.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	signalCalls := 0
	err := reenrollWithSignal(context.Background(), server.URL, "token", ReenrollOptions{
		DataDir: t.TempDir(), SigningKeyPath: filepath.Join(root, "signing.key"), Profile: profile,
	}, func(string) error {
		signalCalls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if signalCalls != 0 || acknowledgements.Load() != 1 {
		t.Fatalf("signal calls=%d acknowledgements=%d", signalCalls, acknowledgements.Load())
	}
}
