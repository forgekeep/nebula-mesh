package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/bootstraptoken"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestMeshImportAPI_CreateGetRotateCancel(t *testing.T) {
	srv, st := newTestServer(t)
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	srv.WithClock(func() time.Time { return now })
	network, ca := seedAPIMeshImportScope(t, st, "lifecycle")

	createBody, _ := json.Marshal(createMeshImportRequest{NetworkID: network.ID, CAID: ca.ID, ExpectedHosts: intPointer(2)})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports", bytes.NewReader(createBody))
	authRequest(request)
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	var created meshImportTokenResponse
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.MeshImport == nil || !strings.HasPrefix(created.Token, "nmi_") {
		t.Fatalf("create response = %#v", created)
	}
	if created.MeshImport.TokenExpiresAt != now.Add(meshImportTokenTTL) {
		t.Fatalf("token expiry = %v", created.MeshImport.TokenExpiresAt)
	}
	var storedHash string
	if err := st.DB().QueryRow(`SELECT token_hash FROM mesh_imports WHERE id = ?`, created.MeshImport.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read stored token: %v", err)
	}
	if storedHash != bootstraptoken.Hash(created.Token) || storedHash == created.Token {
		t.Fatalf("stored token = %q, raw token = %q", storedHash, created.Token)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/mesh-imports/"+created.MeshImport.ID, nil)
	authRequest(request)
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("get status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), created.Token) || strings.Contains(response.Body.String(), storedHash) {
		t.Fatal("GET response disclosed raw token or token hash")
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+created.MeshImport.ID+"/rotate-token", nil)
	authRequest(request)
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("rotate status = %d, body = %s", response.Code, response.Body.String())
	}
	var rotated meshImportTokenResponse
	if err := json.NewDecoder(response.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rotated.Token, "nmi_") || rotated.Token == created.Token {
		t.Fatalf("rotated token = %q", rotated.Token)
	}
	if _, err := st.GetMeshImportByTokenHash(context.Background(), bootstraptoken.Hash(created.Token), now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old token lookup error = %v, want ErrNotFound", err)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+created.MeshImport.ID+"/cancel", nil)
	authRequest(request)
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("cancel status = %d, body = %s", response.Code, response.Body.String())
	}
	var canceled models.MeshImport
	if err := json.NewDecoder(response.Body).Decode(&canceled); err != nil {
		t.Fatal(err)
	}
	if canceled.Status != models.MeshImportStatusCanceled {
		t.Fatalf("cancel status = %q", canceled.Status)
	}
}

func TestMeshImportAPI_TenantIsolation(t *testing.T) {
	srv, st := newTestServer(t)
	network, ca := seedAPIMeshImportScope(t, st, "tenant")
	created := createMeshImportThroughAPI(t, srv, network.ID, ca.ID)
	otherKey := seedAPIOperatorKey(t, st, "other-operator", "other-key")

	request := httptest.NewRequest(http.MethodGet, "/api/v1/mesh-imports/"+created.MeshImport.ID, nil)
	request.Header.Set("Authorization", "Bearer "+otherKey)
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign get status = %d, want 403", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+created.MeshImport.ID+"/rotate-token", nil)
	request.Header.Set("Authorization", "Bearer "+otherKey)
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign rotate status = %d, want 403", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/mesh-imports", nil)
	request.Header.Set("Authorization", "Bearer "+otherKey)
	response = httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), created.MeshImport.ID) {
		t.Fatalf("foreign list status/body = %d %s", response.Code, response.Body.String())
	}
}

func TestMeshImportAPI_RejectsInvalidScope(t *testing.T) {
	srv, st := newTestServer(t)
	firstNetwork, firstCA := seedAPIMeshImportScope(t, st, "mismatch-a")
	secondNetwork, secondCA := seedAPIMeshImportScope(t, st, "mismatch-b")

	tests := []struct {
		name      string
		networkID string
		caID      string
	}{
		{"CA and Network mismatch", firstNetwork.ID, secondCA.ID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, _ := json.Marshal(createMeshImportRequest{NetworkID: test.networkID, CAID: test.caID})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports", bytes.NewReader(body))
			authRequest(request)
			response := httptest.NewRecorder()
			srv.ServeHTTP(response, request)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body = %s", response.Code, response.Body.String())
			}
		})
	}
	_ = secondNetwork
	_ = firstCA
}

func TestMeshImportAPI_FrozenMutationsReturnConflict(t *testing.T) {
	srv, st := newTestServer(t)
	network, ca := seedAPIMeshImportScope(t, st, "freeze")
	createMeshImportThroughAPI(t, srv, network.ID, ca.ID)

	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name: "host create", method: http.MethodPost, path: "/api/v1/hosts",
			body: `{"network_id":"` + network.ID + `","name":"new-host","nebula_ips":["10.` + testOctet("freeze") + `.0.10"],"groups":[],"role":"host"}`,
		},
		{
			name: "firewall update", method: http.MethodPut, path: "/api/v1/networks/" + network.ID + "/firewall",
			body: `{"inbound":[{"port":"any","proto":"icmp","group":"any"}],"outbound":[{"port":"any","proto":"any","group":"any"}]}`,
		},
		{name: "CA rotate", method: http.MethodPost, path: "/api/v1/cas/" + ca.ID + "/rotate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			authRequest(request)
			response := httptest.NewRecorder()
			srv.ServeHTTP(response, request)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMeshImportAPI_RejectsIneligibleScope(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *store.SQLiteStore, *models.Network, *models.CA)
	}{
		{
			name: "retired CA",
			prepare: func(t *testing.T, st *store.SQLiteStore, _ *models.Network, ca *models.CA) {
				t.Helper()
				if err := st.UpdateCAStatus(context.Background(), ca.ID, models.CAStatusRetired); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non-empty Network",
			prepare: func(t *testing.T, st *store.SQLiteStore, network *models.Network, ca *models.CA) {
				t.Helper()
				now := time.Now()
				if err := st.CreateHost(context.Background(), &models.Host{
					ID: "existing-host", NetworkID: network.ID, CAID: ca.ID, Name: "existing-host",
					Role: models.HostRoleHost, Status: models.HostStatusEnrolled, CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "CA bound to another Network",
			prepare: func(t *testing.T, st *store.SQLiteStore, _ *models.Network, ca *models.CA) {
				t.Helper()
				if err := st.CreateNetwork(context.Background(), &models.Network{
					ID: "shared-network", Name: "Shared Network", CIDRs: []string{"10.250.0.0/16"}, CAID: ca.ID, CreatedAt: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "pre-existing CA blocklist",
			prepare: func(t *testing.T, st *store.SQLiteStore, _ *models.Network, ca *models.CA) {
				t.Helper()
				if _, err := st.DB().ExecContext(context.Background(),
					`INSERT INTO blocklist (fingerprint, reason, created_at, ca_id) VALUES (?, ?, ?, ?)`,
					"blocked-fingerprint", "test", time.Now(), ca.ID,
				); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv, st := newTestServer(t)
			network, ca := seedAPIMeshImportScope(t, st, "ineligible-"+strings.ReplaceAll(test.name, " ", "-"))
			test.prepare(t, st, network, ca)
			body, _ := json.Marshal(createMeshImportRequest{NetworkID: network.ID, CAID: ca.ID})
			request := httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports", bytes.NewReader(body))
			authRequest(request)
			response := httptest.NewRecorder()
			srv.ServeHTTP(response, request)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMeshImportAPI_ConcurrentCreateAllowsOneSession(t *testing.T) {
	srv, st := newTestServer(t)
	network, ca := seedAPIMeshImportScope(t, st, "concurrent")
	body, _ := json.Marshal(createMeshImportRequest{NetworkID: network.ID, CAID: ca.ID})

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request := httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports", bytes.NewReader(body))
			authRequest(request)
			response := httptest.NewRecorder()
			srv.ServeHTTP(response, request)
			statuses <- response.Code
		}()
	}
	close(start)
	wait.Wait()
	close(statuses)

	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusCreated] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("statuses = %#v, want one 201 and one 409", counts)
	}
}

func TestMeshImportAPI_PreviewAndFinalizeRequireInventoryAndWarningAcknowledgement(t *testing.T) {
	fixture := newAgentImportFixture(t)
	registered := registerAgentImport(t, fixture)
	emitter := &fakeEmitter{}
	fixture.server.WithEventEmitter(emitter)

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
	if detail.MeshImport == nil || detail.HostCount != 1 || len(detail.Report.Blockers) != 0 || len(detail.WarningAcknowledgements) != 1 {
		t.Fatalf("preview detail = %#v", detail)
	}

	postFinalize := func(body any) *httptest.ResponseRecorder {
		t.Helper()
		encoded, _ := json.Marshal(body)
		request := httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+fixture.sessionID+"/finalize", bytes.NewReader(encoded))
		authRequest(request)
		response := httptest.NewRecorder()
		fixture.server.ServeHTTP(response, request)
		return response
	}
	response = postFinalize(meshImportFinalizeRequest{Revision: detail.MeshImport.Revision})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("incomplete inventory status = %d, body = %s", response.Code, response.Body.String())
	}
	response = postFinalize(meshImportFinalizeRequest{Revision: detail.MeshImport.Revision, InventoryComplete: true})
	if response.Code != http.StatusConflict {
		t.Fatalf("unacknowledged warning status = %d, body = %s", response.Code, response.Body.String())
	}
	response = postFinalize(meshImportFinalizeRequest{
		Revision: detail.MeshImport.Revision, InventoryComplete: true,
		AcknowledgedWarnings: []string{detail.WarningAcknowledgements[0].Key},
	})
	if response.Code != http.StatusOK {
		t.Fatalf("finalize status = %d, body = %s", response.Code, response.Body.String())
	}
	host, err := fixture.store.GetHost(context.Background(), registered.HostID)
	if err != nil || host.Status != models.HostStatusEnrolled {
		t.Fatalf("finalized host = %#v, %v", host, err)
	}
	session, err := fixture.store.GetMeshImport(context.Background(), fixture.sessionID)
	if err != nil {
		t.Fatal(err)
	}
	finalizedEvent, ok := emitter.find("mesh_import.finalized")
	if !ok {
		t.Fatal("mesh_import.finalized event missing")
	}
	if finalizedEvent.scope.CAID != session.CAID {
		t.Errorf("mesh_import.finalized scope CAID = %q, want %q", finalizedEvent.scope.CAID, session.CAID)
	}
	enrolledEvent, ok := emitter.find("host.enrolled")
	if !ok {
		t.Fatal("host.enrolled event missing")
	}
	if enrolledEvent.scope.CAID != session.CAID {
		t.Errorf("host.enrolled scope CAID = %q, want %q", enrolledEvent.scope.CAID, session.CAID)
	}

	response = postFinalize(meshImportFinalizeRequest{
		Revision: detail.MeshImport.Revision, InventoryComplete: true,
		AcknowledgedWarnings: []string{detail.WarningAcknowledgements[0].Key},
	})
	if response.Code != http.StatusConflict {
		t.Fatalf("stale finalize status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestMeshImportAPI_FinalizePreservesRevokedHostAndEmitsBlocked(t *testing.T) {
	fixture := newAgentImportFixture(t)
	fingerprint := certificateFingerprint(t, fixture.snapshot.CertificatePEM)
	fixture.snapshot.Config.Blocklist = []string{fingerprint}
	rehashAgentImportFixture(t, &fixture)
	registered := registerAgentImport(t, fixture)
	emitter := &fakeEmitter{}
	fixture.server.WithEventEmitter(emitter)

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
	if len(detail.Report.Proposal.Hosts) != 1 || detail.Report.Proposal.Hosts[0].Host.Status != models.HostStatusBlocked {
		t.Fatalf("preview hosts = %#v, want blocked", detail.Report.Proposal.Hosts)
	}
	acknowledged := make([]string, 0, len(detail.WarningAcknowledgements))
	for _, warning := range detail.WarningAcknowledgements {
		acknowledged = append(acknowledged, warning.Key)
	}
	body, _ := json.Marshal(meshImportFinalizeRequest{
		Revision: detail.MeshImport.Revision, InventoryComplete: true, AcknowledgedWarnings: acknowledged,
	})
	request = httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+fixture.sessionID+"/finalize", bytes.NewReader(body))
	authRequest(request)
	response = httptest.NewRecorder()
	fixture.server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("finalize status = %d, body = %s", response.Code, response.Body.String())
	}
	host, err := fixture.store.GetHost(t.Context(), registered.HostID)
	if err != nil || host.Status != models.HostStatusBlocked {
		t.Fatalf("finalized host = %#v, %v", host, err)
	}
	if _, ok := emitter.find("host.blocked"); !ok {
		t.Fatal("host.blocked event missing")
	}
	if _, ok := emitter.find("host.enrolled"); ok {
		t.Fatal("revoked imported host emitted host.enrolled")
	}

	poll := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	importedIdentity := enrolledAgent{
		hostID: registered.HostID, fingerprint: registered.Fingerprint, signingPriv: fixture.signingPriv,
	}
	signPoll(t, poll, importedIdentity)
	response = httptest.NewRecorder()
	fixture.server.ServeHTTP(response, poll)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"reason":"revoked"`) {
		t.Fatalf("blocked poll = %d %s", response.Code, response.Body.String())
	}

	finalizedHost, err := fixture.store.GetHost(t.Context(), registered.HostID)
	if err != nil {
		t.Fatal(err)
	}
	sibling := &models.Network{
		ID: "network-import-sibling", Name: "Import sibling", CIDRs: []string{"10.251.0.0/16"},
		CAID: finalizedHost.CAID, CreatedAt: time.Now(),
	}
	if err := fixture.store.CreateNetwork(t.Context(), sibling); err != nil {
		t.Fatal(err)
	}
	peerIdentity := enrollMeshImportPeer(t, fixture.server, sibling.ID)
	otherNetwork, _ := seedAPIMeshImportScope(t, fixture.store, "post-finalize-other-ca")
	otherVersion, err := fixture.store.GetNetworkConfigVersion(t.Context(), otherNetwork.ID)
	if err != nil {
		t.Fatal(err)
	}

	unblock := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+registered.HostID+"/unblock", nil)
	authRequest(unblock)
	response = httptest.NewRecorder()
	fixture.server.ServeHTTP(response, unblock)
	if response.Code != http.StatusOK {
		t.Fatalf("unblock status = %d, body = %s", response.Code, response.Body.String())
	}
	unblockedHost, err := fixture.store.GetHost(t.Context(), registered.HostID)
	if err != nil || unblockedHost.Status != models.HostStatusPending {
		t.Fatalf("unblocked host = %#v, %v", unblockedHost, err)
	}

	poll = httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, poll, importedIdentity)
	response = httptest.NewRecorder()
	fixture.server.ServeHTTP(response, poll)
	if response.Code != http.StatusOK {
		t.Fatalf("unblocked imported poll = %d %s", response.Code, response.Body.String())
	}

	peerPoll := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, peerPoll, peerIdentity)
	response = httptest.NewRecorder()
	fixture.server.ServeHTTP(response, peerPoll)
	if response.Code != http.StatusOK {
		t.Fatalf("sibling peer poll = %d %s", response.Code, response.Body.String())
	}
	var peerUpdates agentUpdatesResponse
	if err := json.NewDecoder(response.Body).Decode(&peerUpdates); err != nil {
		t.Fatal(err)
	}
	if peerUpdates.ConfigYAML == nil || strings.Contains(*peerUpdates.ConfigYAML, fingerprint) || slices.Contains(peerUpdates.Blocklist, fingerprint) {
		t.Fatalf("sibling peer updates retain unblocked fingerprint: %#v", peerUpdates)
	}
	if current, err := fixture.store.GetNetworkConfigVersion(t.Context(), otherNetwork.ID); err != nil || current != otherVersion {
		t.Fatalf("other CA version = %d, %v; want %d", current, err, otherVersion)
	}
}

func enrollMeshImportPeer(t *testing.T, server *Server, networkID string) enrolledAgent {
	t.Helper()
	body, _ := json.Marshal(createHostRequest{
		NetworkID: networkID, Name: "import-sibling-peer", NebulaIPs: []string{"10.251.0.10"},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewReader(body))
	authRequest(request)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create sibling peer = %d %s", response.Code, response.Body.String())
	}
	var created createHostResponse
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	xPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(xPrivate); err != nil {
		t.Fatal(err)
	}
	defer clear(xPrivate)
	xPublic, err := curve25519.X25519(xPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollBody, _ := json.Marshal(enrollRequest{
		Token:         created.EnrollmentToken,
		PublicKeyPEM:  string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, xPublic)),
		SigningPubPEM: string(pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: signingPublic})),
		Profile:       models.DefaultAgentProfile(),
	})
	request = httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(enrollBody))
	response = httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("enroll sibling peer = %d %s", response.Code, response.Body.String())
	}
	var enrolled enrollResponse
	if err := json.NewDecoder(response.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	return enrolledAgent{
		hostID: created.Host.ID, fingerprint: certificateFingerprint(t, enrolled.CertificatePEM),
		signingPub: signingPublic, signingPriv: signingPrivate,
	}
}

func TestMeshImportAPI_FinalizeBlocksReconciliationConflicts(t *testing.T) {
	fixture := newAgentImportFixture(t)
	fixture.snapshot.Config.AmLighthouse = true
	rehashAgentImportFixture(t, &fixture)
	registerAgentImport(t, fixture)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/mesh-imports/"+fixture.sessionID, nil)
	authRequest(request)
	response := httptest.NewRecorder()
	fixture.server.ServeHTTP(response, request)
	var detail meshImportDetailResponse
	if err := json.NewDecoder(response.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if len(detail.Report.Blockers) == 0 {
		t.Fatalf("missing lighthouse endpoint blocker: %#v", detail.Report)
	}
	body, _ := json.Marshal(meshImportFinalizeRequest{Revision: detail.MeshImport.Revision, InventoryComplete: true})
	request = httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports/"+fixture.sessionID+"/finalize", bytes.NewReader(body))
	authRequest(request)
	response = httptest.NewRecorder()
	fixture.server.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("blocked finalize status = %d, body = %s", response.Code, response.Body.String())
	}
}

func createMeshImportThroughAPI(t *testing.T, srv *Server, networkID, caID string) meshImportTokenResponse {
	t.Helper()
	body, _ := json.Marshal(createMeshImportRequest{NetworkID: networkID, CAID: caID})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mesh-imports", bytes.NewReader(body))
	authRequest(request)
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create mesh import: status = %d body = %s", response.Code, response.Body.String())
	}
	var created meshImportTokenResponse
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	return created
}

func seedAPIMeshImportScope(t *testing.T, st *store.SQLiteStore, suffix string) (*models.Network, *models.CA) {
	t.Helper()
	cas, err := st.ListCAsByOwner(context.Background(), "test-admin")
	if err != nil || len(cas) == 0 {
		t.Fatalf("list test CAs: %v, count=%d", err, len(cas))
	}
	ca := *cas[0]
	if suffix != "lifecycle" && suffix != "tenant" && !strings.HasPrefix(suffix, "mismatch-a") {
		ca.ID = "ca-" + suffix
		ca.Name = "CA " + suffix
		ca.Fingerprint = strings.Repeat("a", 63) + string(rune('a'+len(suffix)%20))
		ca.PredecessorID = nil
		if err := st.CreateCA(context.Background(), &ca); err != nil {
			t.Fatalf("create test CA: %v", err)
		}
	}
	network := &models.Network{
		ID: "network-" + suffix, Name: "Network " + suffix,
		CIDRs: []string{"10." + testOctet(suffix) + ".0.0/16"}, CAID: ca.ID, CreatedAt: time.Now(),
	}
	if err := st.CreateNetwork(context.Background(), network); err != nil {
		t.Fatalf("create test Network: %v", err)
	}
	return network, &ca
}

func seedAPIOperatorKey(t *testing.T, st *store.SQLiteStore, operatorID, rawKey string) string {
	t.Helper()
	now := time.Now()
	op := &models.Operator{ID: operatorID, Username: operatorID, PasswordHash: "hash", Role: models.OperatorRoleUser, Status: models.OperatorStatusActive, AuthProvider: models.OperatorAuthLocal, CreatedAt: now, UpdatedAt: now}
	if err := st.CreateOperator(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(rawKey))
	if err := st.CreateOperatorAPIKey(context.Background(), &models.OperatorAPIKey{ID: operatorID + "-key", OperatorID: operatorID, Name: "key", KeyHash: hex.EncodeToString(sum[:])}); err != nil {
		t.Fatal(err)
	}
	return rawKey
}

func testOctet(value string) string {
	sum := sha256.Sum256([]byte(value))
	return strconv.Itoa(1 + int(sum[0])%200)
}

func intPointer(value int) *int { return &value }
