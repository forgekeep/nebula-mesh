package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/importproof"
	"github.com/forgekeep/nebula-mesh/internal/meshimport"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type agentImportFixture struct {
	server      *Server
	store       *store.SQLiteStore
	token       string
	sessionID   string
	caPEM       string
	hostPrivate []byte
	signingPriv ed25519.PrivateKey
	signingPEM  string
	payloadHash string
	snapshot    meshimport.Snapshot
}

func TestAgentImportChallengeAndRegister(t *testing.T) {
	fixture := newAgentImportFixture(t)
	result := registerAgentImport(t, fixture)
	if result.HostID == "" || result.Fingerprint == "" || result.Status != models.HostStatusImporting || !result.Created {
		t.Fatalf("registration response = %#v", result)
	}
	host, err := fixture.store.GetHost(context.Background(), result.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if host.Name != "existing-host" || len(host.NebulaIPs) != 1 || host.SigningPubPEM != fixture.signingPEM {
		t.Fatalf("imported host = %#v", host)
	}
	if _, err := fixture.store.GetCurrentCertificate(context.Background(), host.ID); err != nil {
		t.Fatalf("current certificate: %v", err)
	}
	profile, err := fixture.store.GetHostAgentProfile(context.Background(), host.ID)
	if err != nil || !profile.ConfigAckV1 {
		t.Fatalf("profile = %#v, %v", profile, err)
	}
	auditRows, err := fixture.store.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: auditMeshImportHostRegistered, Limit: 10,
	})
	if err != nil || len(auditRows) != 1 {
		t.Fatalf("registration audit rows = %d, err = %v", len(auditRows), err)
	}
	if strings.Contains(auditRows[0].Details, fixture.token) || strings.Contains(auditRows[0].Details, "BEGIN NEBULA") ||
		strings.Contains(auditRows[0].Details, fixture.signingPEM) {
		t.Fatalf("registration audit leaked secret material: %q", auditRows[0].Details)
	}
}

func TestAgentImportPendingPollDoesNotMutateHost(t *testing.T) {
	fixture := newAgentImportFixture(t)
	result := registerAgentImport(t, fixture)
	agent := enrolledAgent{hostID: result.HostID, fingerprint: result.Fingerprint, signingPriv: fixture.signingPriv}

	hostBefore, err := fixture.store.GetHost(context.Background(), result.HostID)
	if err != nil {
		t.Fatal(err)
	}
	versionBefore, err := fixture.store.GetHostConfigVersion(context.Background(), result.HostID)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, request, agent)
	response := httptest.NewRecorder()
	fixture.server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("poll status = %d; body = %s", response.Code, response.Body.String())
	}
	var updates agentUpdatesResponse
	if err := json.NewDecoder(response.Body).Decode(&updates); err != nil {
		t.Fatal(err)
	}
	if updates.HasUpdates || !updates.ImportPending || updates.CertificatePEM != nil || updates.CACertPEM != nil ||
		updates.ConfigYAML != nil || len(updates.Blocklist) != 0 || updates.RekeyRequired || updates.EnrollmentToken != "" {
		t.Fatalf("pending updates = %#v", updates)
	}
	hostAfter, err := fixture.store.GetHost(context.Background(), result.HostID)
	if err != nil {
		t.Fatal(err)
	}
	versionAfter, err := fixture.store.GetHostConfigVersion(context.Background(), result.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if hostAfter.LastSeenAt != nil || hostAfter.CertFingerprint != hostBefore.CertFingerprint ||
		hostAfter.PendingRekey != hostBefore.PendingRekey || versionAfter != versionBefore {
		t.Fatalf("importing host mutated: before=%#v after=%#v versions=%d/%d", hostBefore, hostAfter, versionBefore, versionAfter)
	}
}

func TestCanceledAgentImportPollRequiresTombstoneSignature(t *testing.T) {
	fixture := newAgentImportFixture(t)
	result := registerAgentImport(t, fixture)
	if err := fixture.store.CancelMeshImport(context.Background(), fixture.sessionID, "operator canceled import", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	agent := enrolledAgent{hostID: result.HostID, fingerprint: result.Fingerprint, signingPriv: fixture.signingPriv}

	badPublic, badPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badRequest := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, badRequest, enrolledAgent{fingerprint: result.Fingerprint, signingPub: badPublic, signingPriv: badPrivate})
	badResponse := httptest.NewRecorder()
	fixture.server.ServeHTTP(badResponse, badRequest)
	if badResponse.Code != http.StatusUnauthorized || strings.Contains(badResponse.Body.String(), "import_canceled") {
		t.Fatalf("unauthenticated tombstone response = %d %s", badResponse.Code, badResponse.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, request, agent)
	response := httptest.NewRecorder()
	fixture.server.ServeHTTP(response, request)
	if response.Code != http.StatusGone || !strings.Contains(response.Body.String(), "import_canceled") {
		t.Fatalf("canceled poll = %d %s", response.Code, response.Body.String())
	}
	replayResponse := httptest.NewRecorder()
	fixture.server.ServeHTTP(replayResponse, request)
	if replayResponse.Code != http.StatusUnauthorized || !strings.Contains(replayResponse.Body.String(), "replayed_nonce") ||
		strings.Contains(replayResponse.Body.String(), "import_canceled") {
		t.Fatalf("replayed tombstone poll = %d %s", replayResponse.Code, replayResponse.Body.String())
	}
}

func TestImportingHostMutationEndpointsReturnConflict(t *testing.T) {
	fixture := newAgentImportFixture(t)
	result := registerAgentImport(t, fixture)
	tests := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPatch, "/api/v1/hosts/" + result.HostID, `{}`},
		{http.MethodDelete, "/api/v1/hosts/" + result.HostID, ""},
		{http.MethodPost, "/api/v1/hosts/" + result.HostID + "/block", ""},
		{http.MethodPost, "/api/v1/hosts/" + result.HostID + "/unblock", ""},
		{http.MethodPost, "/api/v1/hosts/" + result.HostID + "/enrollment-token", ""},
		{http.MethodPost, "/api/v1/hosts/" + result.HostID + "/rotate-cert", ""},
		{http.MethodPost, "/api/v1/hosts/" + result.HostID + "/rotate-cert?new_key=true", ""},
		{http.MethodPost, "/api/v1/hosts/" + result.HostID + "/reenroll", ""},
		{http.MethodPost, "/api/v1/hosts/" + result.HostID + "/mobile-bundle", ""},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			authRequest(request)
			response := httptest.NewRecorder()
			fixture.server.ServeHTTP(response, request)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAgentImportRejectsWrongPurposeAndProof(t *testing.T) {
	fixture := newAgentImportFixture(t)
	wrongPurpose := map[string]any{
		"token": "nme_wrong-purpose", "ca_certificate_pem": fixture.caPEM,
		"agent_signing_public_key_pem": fixture.signingPEM,
		"payload_hash":                 fixture.payloadHash, "snapshot": fixture.snapshot,
	}
	response := postAgentImportJSON(t, fixture.server, "/api/v1/agent/import/challenge", wrongPurpose)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-purpose status = %d; body = %s", response.Code, response.Body.String())
	}

	challenge := requestAgentImportChallenge(t, fixture, http.StatusCreated)
	wrongProof := bytes.Repeat([]byte{0x42}, sha256.Size)
	body := map[string]any{
		"token": fixture.token, "ca_certificate_pem": fixture.caPEM,
		"agent_signing_public_key_pem": fixture.signingPEM,
		"payload_hash":                 fixture.payloadHash, "snapshot": fixture.snapshot,
		"challenge_id": challenge.ChallengeID, "proof": base64.RawURLEncoding.EncodeToString(wrongProof),
	}
	response = postAgentImportJSON(t, fixture.server, "/api/v1/agent/import", body)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "invalid_import_proof") {
		t.Fatalf("wrong-proof status/body = %d %s", response.Code, response.Body.String())
	}
}

func TestAgentImportRejectsInvalidSnapshotBindings(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*testing.T, *agentImportFixture)
		wantStatus int
		wantBody   string
	}{
		{
			name: "multiple configured CA roots", wantStatus: http.StatusBadRequest, wantBody: "invalid_ca_bundle",
			mutate: func(_ *testing.T, fixture *agentImportFixture) {
				fixture.caPEM += fixture.caPEM
			},
		},
		{
			name: "multiple config CA roots", wantStatus: http.StatusBadRequest, wantBody: "invalid_ca_bundle",
			mutate: func(t *testing.T, fixture *agentImportFixture) {
				fixture.snapshot.Config.CARootFingerprints = append(fixture.snapshot.Config.CARootFingerprints, "foreign")
				rehashAgentImportFixture(t, fixture)
			},
		},
		{
			name: "invalid signing key", wantStatus: http.StatusBadRequest, wantBody: "invalid_signing_public_key",
			mutate: func(_ *testing.T, fixture *agentImportFixture) {
				fixture.signingPEM += "trailing-data"
			},
		},
		{
			name: "payload substitution", wantStatus: http.StatusBadRequest, wantBody: "payload_hash_mismatch",
			mutate: func(_ *testing.T, fixture *agentImportFixture) {
				fixture.snapshot.Config.ReportedName = "substituted"
			},
		},
		{
			name: "foreign host certificate", wantStatus: http.StatusBadRequest, wantBody: "invalid_host_certificate",
			mutate: func(t *testing.T, fixture *agentImportFixture) {
				foreignCA, err := pki.NewCA("foreign", 24*time.Hour)
				if err != nil {
					t.Fatal(err)
				}
				defer foreignCA.Wipe()
				hostPublic, err := curve25519.X25519(fixture.hostPrivate, curve25519.Basepoint)
				if err != nil {
					t.Fatal(err)
				}
				certificate, err := foreignCA.Sign(pki.SignRequest{
					Name: "foreign-host", PublicKey: hostPublic,
					Networks: []netip.Prefix{netip.MustParsePrefix("10.200.0.10/16")}, Duration: time.Hour,
				})
				if err != nil {
					t.Fatal(err)
				}
				pemBytes, err := certificate.MarshalPEM()
				if err != nil {
					t.Fatal(err)
				}
				fixture.snapshot.CertificatePEM = string(pemBytes)
				rehashAgentImportFixture(t, fixture)
			},
		},
		{
			name: "expired host certificate", wantStatus: http.StatusBadRequest, wantBody: "invalid_host_certificate",
			mutate: func(t *testing.T, fixture *agentImportFixture) {
				future := time.Now().Add(25 * time.Hour)
				fixture.server.WithClock(func() time.Time { return future })
				if _, err := fixture.store.DB().ExecContext(context.Background(),
					`UPDATE mesh_imports SET token_expires_at = ? WHERE id = ?`, future.Add(time.Hour), fixture.sessionID); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAgentImportFixture(t)
			test.mutate(t, &fixture)
			response := postAgentImportJSON(t, fixture.server, "/api/v1/agent/import/challenge", agentImportChallengeBody(fixture))
			if response.Code != test.wantStatus || !strings.Contains(response.Body.String(), test.wantBody) {
				t.Fatalf("status/body = %d %s, want %d containing %q", response.Code, response.Body.String(), test.wantStatus, test.wantBody)
			}
		})
	}
}

func TestAgentImportRejectsExpiredAndCanceledTokens(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		fixture := newAgentImportFixture(t)
		if _, err := fixture.store.DB().ExecContext(context.Background(),
			`UPDATE mesh_imports SET token_expires_at = ? WHERE id = ?`, time.Now().Add(-time.Minute), fixture.sessionID); err != nil {
			t.Fatal(err)
		}
		response := postAgentImportJSON(t, fixture.server, "/api/v1/agent/import/challenge", agentImportChallengeBody(fixture))
		if response.Code != http.StatusGone || !strings.Contains(response.Body.String(), "import_token_expired") {
			t.Fatalf("expired token = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("canceled", func(t *testing.T) {
		fixture := newAgentImportFixture(t)
		if err := fixture.store.CancelMeshImport(context.Background(), fixture.sessionID, "canceled", time.Now()); err != nil {
			t.Fatal(err)
		}
		response := postAgentImportJSON(t, fixture.server, "/api/v1/agent/import/challenge", agentImportChallengeBody(fixture))
		if response.Code != http.StatusGone || !strings.Contains(response.Body.String(), "import_not_collecting") {
			t.Fatalf("canceled token = %d %s", response.Code, response.Body.String())
		}
	})
}

func TestAgentImportChallengeExpiryReplayAndIdempotency(t *testing.T) {
	t.Run("expired challenge", func(t *testing.T) {
		fixture := newAgentImportFixture(t)
		now := time.Now()
		fixture.server.WithClock(func() time.Time { return now })
		challenge := requestAgentImportChallenge(t, fixture, http.StatusCreated)
		proof := computeAgentImportProof(t, fixture, challenge)
		now = now.Add(agentImportChallengeTTL)
		response := submitAgentImport(t, fixture, challenge, proof)
		if response.Code != http.StatusGone || !strings.Contains(response.Body.String(), "import_challenge_expired") {
			t.Fatalf("expired challenge = %d %s", response.Code, response.Body.String())
		}
	})
	t.Run("replay and idempotent retry", func(t *testing.T) {
		fixture := newAgentImportFixture(t)
		challenge := requestAgentImportChallenge(t, fixture, http.StatusCreated)
		proof := computeAgentImportProof(t, fixture, challenge)
		first := submitAgentImport(t, fixture, challenge, proof)
		if first.Code != http.StatusCreated {
			t.Fatalf("first import = %d %s", first.Code, first.Body.String())
		}
		var created agentImportResult
		if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
			t.Fatal(err)
		}
		replay := submitAgentImport(t, fixture, challenge, proof)
		if replay.Code != http.StatusConflict {
			t.Fatalf("challenge replay = %d %s", replay.Code, replay.Body.String())
		}
		retryChallenge := requestAgentImportChallenge(t, fixture, http.StatusCreated)
		retry := submitAgentImport(t, fixture, retryChallenge, computeAgentImportProof(t, fixture, retryChallenge))
		if retry.Code != http.StatusOK {
			t.Fatalf("idempotent retry = %d %s", retry.Code, retry.Body.String())
		}
		var existing agentImportResult
		if err := json.Unmarshal(retry.Body.Bytes(), &existing); err != nil {
			t.Fatal(err)
		}
		if existing.Created || existing.HostID != created.HostID || existing.Fingerprint != created.Fingerprint {
			t.Fatalf("idempotent result = %#v, created = %#v", existing, created)
		}
	})
}

func TestAgentImportRequestBodyIsBounded(t *testing.T) {
	fixture := newAgentImportFixture(t)
	oversized := append([]byte(`{"token":"`), bytes.Repeat([]byte("x"), 2<<20)...)
	oversized = append(oversized, []byte(`"}`)...)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/agent/import/challenge", bytes.NewReader(oversized))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	fixture.server.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413; body = %s", response.Code, response.Body.String())
	}
}

type testAgentImportChallengeResponse struct {
	ChallengeID     string    `json:"challenge_id"`
	SessionID       string    `json:"session_id"`
	ServerPublicKey string    `json:"server_public_key"`
	ServerNonce     string    `json:"server_nonce"`
	ExpiresAt       time.Time `json:"expires_at"`
}

func newAgentImportFixture(t *testing.T) agentImportFixture {
	t.Helper()
	srv, st := newTestServer(t)
	network, ca := seedAPIMeshImportScope(t, st, "lifecycle")
	created := createMeshImportThroughAPI(t, srv, network.ID, ca.ID)

	hostPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(hostPrivate); err != nil {
		t.Fatal(err)
	}
	hostPublic, err := curve25519.X25519(hostPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	caManager, err := srv.caForHost(context.Background(), &models.Host{CAID: ca.ID})
	if err != nil {
		t.Fatal(err)
	}
	defer caManager.Wipe()
	hostCertificate, err := caManager.Sign(pki.SignRequest{
		Name: "existing-host", PublicKey: hostPublic,
		Networks: []netip.Prefix{netip.MustParsePrefix("10." + testOctet("lifecycle") + ".0.10/16")},
		Groups:   []string{"prod"}, Duration: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostCertPEM, err := hostCertificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPEM := string(pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: signingPublic}))
	snapshot := meshimport.Snapshot{
		ID: "local-snapshot", HostID: "local-host", CertificatePEM: string(hostCertPEM),
		Profile: meshimport.AgentProfile{
			NebulaConfigPath: "/etc/nebula/config.yml", NebulaCAPath: "/etc/nebula/ca.crt",
			NebulaCertPath: "/etc/nebula/host.crt", NebulaKeyPath: "/etc/nebula/host.key", ConfigAckV1: true,
		},
		Config: meshimport.ConfigSnapshot{CARootFingerprints: []string{ca.Fingerprint}},
	}
	payloadJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	payloadSum := sha256.Sum256(payloadJSON)
	return agentImportFixture{
		server: srv, store: st, token: created.Token, sessionID: created.MeshImport.ID,
		caPEM: ca.CertPEM, hostPrivate: hostPrivate, signingPriv: signingPrivate, signingPEM: signingPEM,
		payloadHash: hex.EncodeToString(payloadSum[:]), snapshot: snapshot,
	}
}

type agentImportResult struct {
	HostID      string            `json:"host_id"`
	Fingerprint string            `json:"certificate_fingerprint"`
	Status      models.HostStatus `json:"status"`
	Created     bool              `json:"created"`
}

func registerAgentImport(t *testing.T, fixture agentImportFixture) agentImportResult {
	t.Helper()
	challenge := requestAgentImportChallenge(t, fixture, http.StatusCreated)
	proof := computeAgentImportProof(t, fixture, challenge)
	body := map[string]any{
		"token": fixture.token, "ca_certificate_pem": fixture.caPEM,
		"agent_signing_public_key_pem": fixture.signingPEM,
		"payload_hash":                 fixture.payloadHash, "snapshot": fixture.snapshot,
		"challenge_id": challenge.ChallengeID, "proof": base64.RawURLEncoding.EncodeToString(proof),
	}
	response := postAgentImportJSON(t, fixture.server, "/api/v1/agent/import", body)
	if response.Code != http.StatusCreated {
		t.Fatalf("register status = %d; body = %s", response.Code, response.Body.String())
	}
	var result agentImportResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.HostID == "" || result.Fingerprint == "" || result.Status != models.HostStatusImporting || !result.Created {
		t.Fatalf("registration response = %#v", result)
	}
	return result
}

func requestAgentImportChallenge(t *testing.T, fixture agentImportFixture, wantStatus int) testAgentImportChallengeResponse {
	t.Helper()
	response := postAgentImportJSON(t, fixture.server, "/api/v1/agent/import/challenge", agentImportChallengeBody(fixture))
	if response.Code != wantStatus {
		t.Fatalf("challenge status = %d, want %d; body = %s", response.Code, wantStatus, response.Body.String())
	}
	var challenge testAgentImportChallengeResponse
	if err := json.NewDecoder(response.Body).Decode(&challenge); err != nil {
		t.Fatal(err)
	}
	return challenge
}

func agentImportChallengeBody(fixture agentImportFixture) map[string]any {
	return map[string]any{
		"token": fixture.token, "ca_certificate_pem": fixture.caPEM,
		"agent_signing_public_key_pem": fixture.signingPEM,
		"payload_hash":                 fixture.payloadHash, "snapshot": fixture.snapshot,
	}
}

func submitAgentImport(
	t *testing.T,
	fixture agentImportFixture,
	challenge testAgentImportChallengeResponse,
	proof []byte,
) *httptest.ResponseRecorder {
	t.Helper()
	body := agentImportChallengeBody(fixture)
	body["challenge_id"] = challenge.ChallengeID
	body["proof"] = base64.RawURLEncoding.EncodeToString(proof)
	return postAgentImportJSON(t, fixture.server, "/api/v1/agent/import", body)
}

func rehashAgentImportFixture(t *testing.T, fixture *agentImportFixture) {
	t.Helper()
	payloadJSON, err := json.Marshal(fixture.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	payloadSum := sha256.Sum256(payloadJSON)
	fixture.payloadHash = hex.EncodeToString(payloadSum[:])
}

func computeAgentImportProof(t *testing.T, fixture agentImportFixture, challenge testAgentImportChallengeResponse) []byte {
	t.Helper()
	serverPublic, err := base64.RawURLEncoding.DecodeString(challenge.ServerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.ServerNonce)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := importproof.Compute(fixture.hostPrivate, serverPublic, nonce, importproof.Binding{
		SessionID: fixture.sessionID, CertificateFingerprint: certificateFingerprint(t, fixture.snapshot.CertificatePEM),
		AgentSigningPublicKeyPEM: fixture.signingPEM, PayloadHash: fixture.payloadHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func certificateFingerprint(t *testing.T, certificatePEM string) string {
	t.Helper()
	certificate, _, err := cert.UnmarshalCertificateFromPEM([]byte(certificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := certificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func postAgentImportJSON(t *testing.T, srv *Server, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	return response
}
