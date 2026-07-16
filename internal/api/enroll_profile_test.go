package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestEnrollPersistsCustomAgentProfileWithSigningIdentity(t *testing.T) {
	srv, sqliteStore := newTestServer(t)
	networkID := createNetwork(t, srv)
	body, _ := json.Marshal(createHostRequest{NetworkID: networkID, Name: "profile-host", NebulaIPs: []string{"192.168.100.41"}})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(body))
	authRequest(request)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("create host: %d %s", recorder.Code, recorder.Body.String())
	}
	var created createHostResponse
	_ = json.NewDecoder(recorder.Body).Decode(&created)

	privateKey := make([]byte, curve25519.ScalarSize)
	_, _ = rand.Read(privateKey)
	defer clear(privateKey)
	publicKey, _ := curve25519.X25519(privateKey, curve25519.Basepoint)
	signingPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	signingPEM := pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: signingPublic})
	profile := models.AgentProfile{
		NebulaConfigPath: "/custom/nebula/node.yml", NebulaCAPath: "/custom/pki/root.pem",
		NebulaCertPath: "/custom/pki/node.pem", NebulaKeyPath: "/custom/pki/node.key", ConfigAckV1: true,
	}
	enrollBody, _ := json.Marshal(enrollRequest{
		Token: created.EnrollmentToken, PublicKeyPEM: string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, publicKey)),
		SigningPubPEM: string(signingPEM), Profile: profile,
	})
	recorder = httptest.NewRecorder()
	srv.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(enrollBody)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("enroll: %d %s", recorder.Code, recorder.Body.String())
	}
	stored, err := sqliteStore.GetHostAgentProfile(t.Context(), created.Host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AgentProfile() != profile || stored.MeshImportID != "" {
		t.Fatalf("stored profile = %#v", stored)
	}
	host, err := sqliteStore.GetHost(t.Context(), created.Host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if host.SigningPubPEM != string(signingPEM) {
		t.Fatal("signing identity was not persisted with enrollment")
	}
	var response enrollResponse
	_ = json.NewDecoder(recorder.Body).Decode(&response)
	if !strings.Contains(response.ConfigYAML, profile.NebulaCertPath) {
		t.Fatalf("rendered enrollment config ignored profile: %s", response.ConfigYAML)
	}
}
