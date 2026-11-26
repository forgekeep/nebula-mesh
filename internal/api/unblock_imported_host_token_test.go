package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func finalizeImportedHost(t *testing.T, fixture agentImportFixture) agentImportResult {
	t.Helper()
	registered := registerAgentImport(t, fixture)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/mesh-imports/"+fixture.sessionID, nil)
	authRequest(request)
	response := httptest.NewRecorder()
	fixture.server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("preview status = %d, body = %s", response.Code, response.Body.String())
	}
	var detail meshImportDetailResponse
	if err := json.NewDecoder(response.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	acks := make([]string, 0, len(detail.WarningAcknowledgements))
	for _, warning := range detail.WarningAcknowledgements {
		acks = append(acks, warning.Key)
	}
	body, err := json.Marshal(meshImportFinalizeRequest{
		Revision: detail.MeshImport.Revision, InventoryComplete: true, AcknowledgedWarnings: acks,
	})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+fixture.sessionID+"/finalize", bytes.NewReader(body))
	authRequest(request)
	response = httptest.NewRecorder()
	fixture.server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("finalize status = %d, body = %s", response.Code, response.Body.String())
	}
	host, err := fixture.store.GetHost(t.Context(), registered.HostID)
	if err != nil || host.Status != models.HostStatusEnrolled {
		t.Fatalf("finalized host = %#v, %v", host, err)
	}
	return registered
}

func buildEnrollmentBody(t *testing.T, token string) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	x25519Private := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(x25519Private); err != nil {
		t.Fatal(err)
	}
	x25519Public, err := curve25519.X25519(x25519Private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	ed25519Public, ed25519Private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(enrollRequest{
		Token:         token,
		PublicKeyPEM:  string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, x25519Public)),
		SigningPubPEM: string(pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: ed25519Public})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return body, ed25519Private
}

func postEnrollment(t *testing.T, srv *Server, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	return response
}

func postHostAction(t *testing.T, srv *Server, hostID, action string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+hostID+"/"+action, nil)
	authRequest(request)
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	return response
}

func mintReenrollmentToken(t *testing.T, srv *Server, hostID string) string {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+hostID+"/reenroll", nil)
	authRequest(request)
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("mint re-enrollment token: %d %s", response.Code, response.Body.String())
	}
	var tokenResponse regenerateEnrollmentTokenResponse
	if err := json.NewDecoder(response.Body).Decode(&tokenResponse); err != nil {
		t.Fatal(err)
	}
	return tokenResponse.Token
}

func TestImportedHostPreBlockToken_SEC_REPLAY_001_CannotReplaceIdentityAfterUnblock(t *testing.T) {
	fixture := newAgentImportFixture(t)
	registered := finalizeImportedHost(t, fixture)
	initialHost, err := fixture.store.GetHost(t.Context(), registered.HostID)
	if err != nil {
		t.Fatal(err)
	}
	token := mintReenrollmentToken(t, fixture.server, registered.HostID)
	body, _ := buildEnrollmentBody(t, token)

	if blocked := postHostAction(t, fixture.server, registered.HostID, "block"); blocked.Code != http.StatusOK {
		t.Fatalf("block imported host: %d %s", blocked.Code, blocked.Body.String())
	}
	if _, err := fixture.store.GetEnrollmentToken(t.Context(), token); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("pre-block token lookup after block = %v, want ErrNotFound", err)
	}
	if blockedEnroll := postEnrollment(t, fixture.server, body); blockedEnroll.Code != http.StatusUnauthorized {
		t.Fatalf("enrollment with invalidated token while blocked = %d %s, want 401", blockedEnroll.Code, blockedEnroll.Body.String())
	}
	if unblocked := postHostAction(t, fixture.server, registered.HostID, "unblock"); unblocked.Code != http.StatusOK {
		t.Fatalf("unblock imported host: %d %s", unblocked.Code, unblocked.Body.String())
	}
	if rejected := postEnrollment(t, fixture.server, body); rejected.Code != http.StatusUnauthorized {
		t.Fatalf("pre-block token after unblock = %d %s, want 401", rejected.Code, rejected.Body.String())
	}
	currentHost, err := fixture.store.GetHost(t.Context(), registered.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if currentHost.CertFingerprint != initialHost.CertFingerprint || currentHost.SigningPubPEM != initialHost.SigningPubPEM {
		t.Fatal("rejected pre-block token changed imported host identity")
	}

	freshToken := mintReenrollmentToken(t, fixture.server, registered.HostID)
	freshBody, freshSigningPrivate := buildEnrollmentBody(t, freshToken)
	accepted := postEnrollment(t, fixture.server, freshBody)
	if accepted.Code != http.StatusOK {
		t.Fatalf("fresh post-unblock token = %d %s, want 200", accepted.Code, accepted.Body.String())
	}
	var enrolled enrollResponse
	if err := json.NewDecoder(accepted.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	updatedHost, err := fixture.store.GetHost(t.Context(), registered.HostID)
	if err != nil {
		t.Fatal(err)
	}
	poll := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, poll, enrolledAgent{
		hostID: registered.HostID, fingerprint: updatedHost.CertFingerprint, signingPriv: freshSigningPrivate,
	})
	pollResponse := httptest.NewRecorder()
	fixture.server.ServeHTTP(pollResponse, poll)
	if pollResponse.Code != http.StatusOK {
		t.Fatalf("fresh post-unblock identity poll = %d %s", pollResponse.Code, pollResponse.Body.String())
	}
}

func TestOrdinaryHostPreBlockToken_SEC_REPLAY_001_RejectedAfterUnblock(t *testing.T) {
	srv, _ := newTestServer(t)
	networkID := createNetwork(t, srv)
	body, err := json.Marshal(createHostRequest{NetworkID: networkID, Name: "ordinary-token-control", NebulaIPs: []string{"192.168.100.200"}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(body))
	authRequest(request)
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create ordinary host = %d, want 201; body = %s", response.Code, response.Body.String())
	}
	var created createHostResponse
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	enrollBody, _ := buildEnrollmentBody(t, created.EnrollmentToken)
	if blocked := postHostAction(t, srv, created.Host.ID, "block"); blocked.Code != http.StatusOK {
		t.Fatalf("block ordinary host = %d %s", blocked.Code, blocked.Body.String())
	}
	if _, err := srv.store.GetEnrollmentToken(t.Context(), created.EnrollmentToken); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("ordinary token lookup after block = %v, want ErrNotFound", err)
	}
	if unblocked := postHostAction(t, srv, created.Host.ID, "unblock"); unblocked.Code != http.StatusOK {
		t.Fatalf("unblock ordinary host = %d %s", unblocked.Code, unblocked.Body.String())
	}
	if rejected := postEnrollment(t, srv, enrollBody); rejected.Code != http.StatusUnauthorized {
		t.Fatalf("ordinary pre-block token after unblock = %d %s, want 401", rejected.Code, rejected.Body.String())
	}
}
