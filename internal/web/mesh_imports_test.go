package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/meshimport"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/webhook"
)

var meshImportTokenPattern = regexp.MustCompile(`nmi_[A-Za-z0-9_-]+`)

type webCapturedEvent struct {
	scope webhook.Scope
	typ   string
}

type webFakeEmitter struct {
	mu     sync.Mutex
	events []webCapturedEvent
}

func (f *webFakeEmitter) Emit(scope webhook.Scope, eventType string, _ map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, webCapturedEvent{scope: scope, typ: eventType})
}

func (f *webFakeEmitter) find(eventType string) (webCapturedEvent, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, event := range f.events {
		if event.typ == eventType {
			return event, true
		}
	}
	return webCapturedEvent{}, false
}

func TestMeshImportWebCreateShowsTokenOnceAndUsesCSRF(t *testing.T) {
	w, st := newTestWeb(t)
	ca := seedActiveCA(t, st, "mesh-ca", "admin-test-id", "Mesh CA")
	network := &models.Network{ID: "mesh-network", Name: "Mesh Network", CIDRs: []string{"10.70.0.0/16"}, CAID: ca.ID, CreatedAt: time.Now()}
	if err := st.CreateNetwork(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	cookies := loginSession(t, w)
	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/mesh-imports/new", cookies)
	form := url.Values{
		"network_id": {network.ID}, "ca_id": {ca.ID}, "expected_hosts": {"2"}, "_csrf": {csrfToken},
	}
	request := httptest.NewRequest(http.MethodPost, "/ui/mesh-imports", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	w.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", response.Code, response.Body.String())
	}
	rawToken := meshImportTokenPattern.FindString(response.Body.String())
	if rawToken == "" {
		t.Fatalf("one-time nmi_ token missing from response: %s", response.Body.String())
	}
	items, err := st.ListMeshImportsByOwner(context.Background(), "admin-test-id")
	if err != nil || len(items) != 1 {
		t.Fatalf("list imports: err=%v count=%d", err, len(items))
	}
	if !strings.HasPrefix(items[0].TokenHash, "hmac-sha256-v1:") || items[0].TokenHash == rawToken {
		t.Fatalf("stored hash = %q", items[0].TokenHash)
	}

	request = httptest.NewRequest(http.MethodGet, "/ui/mesh-imports/"+items[0].ID, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response = httptest.NewRecorder()
	w.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("detail status = %d", response.Code)
	}
	if strings.Contains(response.Body.String(), rawToken) || strings.Contains(response.Body.String(), items[0].TokenHash) {
		t.Fatal("detail page disclosed raw token or hash")
	}
}

func TestMeshImportWebCreateRejectsMissingCSRF(t *testing.T) {
	w, st := newTestWeb(t)
	ca := seedActiveCA(t, st, "csrf-ca", "admin-test-id", "CSRF CA")
	network := &models.Network{ID: "csrf-network", Name: "CSRF Network", CIDRs: []string{"10.71.0.0/16"}, CAID: ca.ID, CreatedAt: time.Now()}
	if err := st.CreateNetwork(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	cookies := loginSession(t, w)
	form := url.Values{"network_id": {network.ID}, "ca_id": {ca.ID}}
	request := httptest.NewRequest(http.MethodPost, "/ui/mesh-imports", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	w.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestMeshImportWebTenantIsolation(t *testing.T) {
	w, st := newOperatorsWeb(t)
	aliceCookie := mintSession(t, st, "alice", "user")
	mintSession(t, st, "bob", "user")
	ca := seedActiveCA(t, st, "bob-import-ca", "op-bob", "Bob import CA")
	network := &models.Network{ID: "bob-import-network", Name: "Bob import Network", CIDRs: []string{"10.72.0.0/16"}, CAID: ca.ID, CreatedAt: time.Now()}
	if err := st.CreateNetwork(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	item := &models.MeshImport{
		ID: "bob-import", NetworkID: network.ID, CAID: ca.ID, OwnerOperatorID: "op-bob",
		Status:         models.MeshImportStatusCollecting,
		TokenExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateMeshImport(context.Background(), item, "nmi_bob"); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/ui/mesh-imports/"+item.ID, nil)
	request.AddCookie(aliceCookie)
	response := httptest.NewRecorder()
	w.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign detail status = %d, want 403", response.Code)
	}
}

func TestMeshImportWebPreviewAndFinalize(t *testing.T) {
	w, st := newOperatorsWebWithMaster(t)
	emitter := &webFakeEmitter{}
	w.WithLifecycleEventEmitter(emitter)
	cookie := mintSession(t, st, "adopter", "admin")
	op, err := st.GetOperatorByUsername(context.Background(), "adopter")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := w.mintCAForOperator(context.Background(), op, "adopt-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	network := &models.Network{ID: "adopt-network", Name: "Adopt Network", CIDRs: []string{"10.75.0.0/16"}, CAID: ca.ID, CreatedAt: time.Now()}
	if err := st.CreateNetwork(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := &models.MeshImport{
		ID: "adopt-import", NetworkID: network.ID, CAID: ca.ID, OwnerOperatorID: op.ID,
		Status:         models.MeshImportStatusCollecting,
		TokenExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateMeshImport(context.Background(), session, "nmi_adopt"); err != nil {
		t.Fatal(err)
	}
	resolver := pki.NewCAResolver(st, w.caMaster)
	manager, err := resolver.LoadByID(context.Background(), ca.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Wipe()
	hostCertificate, err := manager.Sign(pki.SignRequest{
		Name: "adopted-host", PublicKey: make([]byte, 32), Networks: []netip.Prefix{netip.MustParsePrefix("10.75.0.10/16")},
		Groups: []string{"prod"}, Duration: 90 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, err := hostCertificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := meshimport.Snapshot{
		ID: "snapshot-adopt", HostID: "host-adopt", CertificatePEM: string(hostPEM),
		Profile: models.DefaultAgentProfile(),
		Config: meshimport.ConfigSnapshot{
			CARootFingerprints: []string{ca.Fingerprint}, Firewall: meshimport.FirewallPolicy{},
		},
	}
	report := meshimport.Reconcile(meshimport.ReconcileInput{
		NetworkID: network.ID, CAID: ca.ID, NetworkCIDRs: network.CIDRs,
		CACertificatePEM: ca.CertPEM, CAFingerprint: ca.Fingerprint, Snapshots: []meshimport.Snapshot{snapshot}, Now: now,
	})
	if len(report.Blockers) != 0 || len(report.Proposal.Hosts) != 1 {
		t.Fatalf("fixture reconcile = %#v", report)
	}
	host := report.Proposal.Hosts[0].Host
	host.SigningPubPEM = "test-signing-key"
	host.CreatedAt, host.UpdatedAt = now, now
	fingerprint, err := hostCertificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	challenge := &models.MeshImportChallenge{
		ID: "challenge-adopt", MeshImportID: session.ID, TokenHash: session.TokenHash, CertificateFingerprint: fingerprint,
		AgentSigningPubPEM: host.SigningPubPEM, PayloadHash: "payload-adopt", ServerNonce: "nonce-adopt",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}
	if err := st.CreateMeshImportChallenge(context.Background(), challenge, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RegisterImportedHost(context.Background(), &models.MeshImportRegistration{
		ChallengeID: challenge.ID, CertificateNotBefore: hostCertificate.NotBefore(), CertificateNotAfter: hostCertificate.NotAfter(), Host: &host,
		Snapshot: &models.MeshImportSnapshot{
			ID: snapshot.ID, MeshImportID: session.ID, HostID: host.ID, CertificateFingerprint: fingerprint,
			CertificatePEM: string(hostPEM), AgentSigningPubPEM: host.SigningPubPEM, PayloadHash: challenge.PayloadHash,
			SnapshotJSON: string(encodedSnapshot), CreatedAt: now, UpdatedAt: now,
		},
		Profile: &models.HostAgentProfile{
			HostID: host.ID, MeshImportID: session.ID, NebulaConfigPath: snapshot.Profile.NebulaConfigPath,
			NebulaCAPath: snapshot.Profile.NebulaCAPath, NebulaCertPath: snapshot.Profile.NebulaCertPath,
			NebulaKeyPath: snapshot.Profile.NebulaKeyPath, CreatedAt: now, UpdatedAt: now,
		},
	}, now); err != nil {
		t.Fatal(err)
	}

	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/mesh-imports/"+session.ID, []*http.Cookie{cookie})
	get := httptest.NewRequest(http.MethodGet, "/ui/mesh-imports/"+session.ID, nil)
	for _, current := range cookies {
		get.AddCookie(current)
	}
	page := httptest.NewRecorder()
	w.ServeHTTP(page, get)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "Normalized proposal") || !strings.Contains(page.Body.String(), "adopted-host") {
		t.Fatalf("preview page = %d / %s", page.Code, page.Body.String())
	}
	form := url.Values{"revision": {"1"}, "inventory_complete": {"true"}, "_csrf": {csrfToken}}
	request := httptest.NewRequest(http.MethodPost, "/ui/mesh-imports/"+session.ID+"/finalize", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, current := range cookies {
		request.AddCookie(current)
	}
	response := httptest.NewRecorder()
	w.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("finalize status = %d, body = %s", response.Code, response.Body.String())
	}
	finalHost, err := st.GetHost(context.Background(), host.ID)
	if err != nil || finalHost.Status != models.HostStatusEnrolled {
		t.Fatalf("finalized host = %#v, %v", finalHost, err)
	}
	for _, eventType := range []string{"mesh_import.finalized", "host.enrolled"} {
		event, ok := emitter.find(eventType)
		if !ok {
			t.Fatalf("%s event missing", eventType)
		}
		if event.scope.CAID != ca.ID {
			t.Errorf("%s scope CAID = %q, want %q", eventType, event.scope.CAID, ca.ID)
		}
	}
}

func TestMeshImportWebFinalizePreservesRevokedHostAndEmitsBlocked(t *testing.T) {
	w, st := newOperatorsWebWithMaster(t)
	emitter := &webFakeEmitter{}
	w.WithLifecycleEventEmitter(emitter)
	cookie := mintSession(t, st, "blocked-adopter", "admin")
	op, err := st.GetOperatorByUsername(t.Context(), "blocked-adopter")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := w.mintCAForOperator(t.Context(), op, "blocked-adopt-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	network := &models.Network{
		ID: "blocked-adopt-network", Name: "Blocked Adopt Network", CIDRs: []string{"10.76.0.0/16"},
		CAID: ca.ID, CreatedAt: time.Now(),
	}
	if err := st.CreateNetwork(t.Context(), network); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session := &models.MeshImport{
		ID: "blocked-adopt-import", NetworkID: network.ID, CAID: ca.ID, OwnerOperatorID: op.ID,
		Status:         models.MeshImportStatusCollecting,
		TokenExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateMeshImport(t.Context(), session, "nmi_blocked_adopt"); err != nil {
		t.Fatal(err)
	}
	resolver := pki.NewCAResolver(st, w.caMaster)
	manager, err := resolver.LoadByID(t.Context(), ca.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Wipe()
	hostCertificate, err := manager.Sign(pki.SignRequest{
		Name: "blocked-adopted-host", PublicKey: make([]byte, 32),
		Networks: []netip.Prefix{netip.MustParsePrefix("10.76.0.10/16")}, Groups: []string{"prod"},
		Duration: 90 * 24 * time.Hour, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	hostPEM, err := hostCertificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := hostCertificate.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	snapshot := meshimport.Snapshot{
		ID: "snapshot-blocked-adopt", HostID: "host-blocked-adopt", CertificatePEM: string(hostPEM),
		Profile: models.DefaultAgentProfile(),
		Config: meshimport.ConfigSnapshot{
			CARootFingerprints: []string{ca.Fingerprint}, Firewall: meshimport.FirewallPolicy{},
			Blocklist: []string{fingerprint},
		},
	}
	report := meshimport.Reconcile(meshimport.ReconcileInput{
		NetworkID: network.ID, CAID: ca.ID, NetworkCIDRs: network.CIDRs,
		CACertificatePEM: ca.CertPEM, CAFingerprint: ca.Fingerprint, Snapshots: []meshimport.Snapshot{snapshot}, Now: now,
	})
	if len(report.Blockers) != 0 || len(report.Proposal.Hosts) != 1 ||
		report.Proposal.Hosts[0].Host.Status != models.HostStatusBlocked {
		t.Fatalf("fixture reconcile = %#v", report)
	}
	proposalHost := report.Proposal.Hosts[0].Host
	stagedHost := proposalHost
	stagedHost.Status = models.HostStatusImporting
	stagedHost.SigningPubPEM = "test-signing-key"
	stagedHost.CreatedAt, stagedHost.UpdatedAt = now, now
	encodedSnapshot, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	challenge := &models.MeshImportChallenge{
		ID: "challenge-blocked-adopt", MeshImportID: session.ID, TokenHash: session.TokenHash,
		CertificateFingerprint: fingerprint, AgentSigningPubPEM: stagedHost.SigningPubPEM,
		PayloadHash: "payload-blocked-adopt", ServerNonce: "nonce-blocked-adopt",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}
	if err := st.CreateMeshImportChallenge(t.Context(), challenge, now); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RegisterImportedHost(t.Context(), &models.MeshImportRegistration{
		ChallengeID: challenge.ID, CertificateNotBefore: hostCertificate.NotBefore(),
		CertificateNotAfter: hostCertificate.NotAfter(), Host: &stagedHost,
		Snapshot: &models.MeshImportSnapshot{
			ID: snapshot.ID, MeshImportID: session.ID, HostID: stagedHost.ID,
			CertificateFingerprint: fingerprint, CertificatePEM: string(hostPEM),
			AgentSigningPubPEM: stagedHost.SigningPubPEM, PayloadHash: challenge.PayloadHash,
			SnapshotJSON: string(encodedSnapshot), CreatedAt: now, UpdatedAt: now,
		},
		Profile: &models.HostAgentProfile{
			HostID: stagedHost.ID, MeshImportID: session.ID, NebulaConfigPath: snapshot.Profile.NebulaConfigPath,
			NebulaCAPath: snapshot.Profile.NebulaCAPath, NebulaCertPath: snapshot.Profile.NebulaCertPath,
			NebulaKeyPath: snapshot.Profile.NebulaKeyPath, ConfigAckV1: true, CreatedAt: now, UpdatedAt: now,
		},
	}, now); err != nil {
		t.Fatal(err)
	}

	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/mesh-imports/"+session.ID, []*http.Cookie{cookie})
	get := httptest.NewRequest(http.MethodGet, "/ui/mesh-imports/"+session.ID, nil)
	for _, current := range cookies {
		get.AddCookie(current)
	}
	page := httptest.NewRecorder()
	w.ServeHTTP(page, get)
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "blocked") {
		t.Fatalf("blocked preview page = %d / %s", page.Code, page.Body.String())
	}
	form := url.Values{"revision": {"1"}, "inventory_complete": {"true"}, "_csrf": {csrfToken}}
	request := httptest.NewRequest(http.MethodPost, "/ui/mesh-imports/"+session.ID+"/finalize", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, current := range cookies {
		request.AddCookie(current)
	}
	response := httptest.NewRecorder()
	w.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("finalize status = %d, body = %s", response.Code, response.Body.String())
	}
	finalHost, err := st.GetHost(t.Context(), stagedHost.ID)
	if err != nil || finalHost.Status != models.HostStatusBlocked {
		t.Fatalf("finalized host = %#v, %v", finalHost, err)
	}
	if _, ok := emitter.find("host.blocked"); !ok {
		t.Fatal("host.blocked event missing")
	}
	if _, ok := emitter.find("host.enrolled"); ok {
		t.Fatal("revoked imported host emitted host.enrolled")
	}
}

func TestMeshImportWebFrozenMutationsReturnConflict(t *testing.T) {
	w, st := newOperatorsWebWithMaster(t)
	cookie := mintSession(t, st, "freeze-admin", "admin")
	op, err := st.GetOperatorByUsername(context.Background(), "freeze-admin")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := w.mintCAForOperator(context.Background(), op, "freeze-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	network := &models.Network{ID: "freeze-network", Name: "Freeze Network", CIDRs: []string{"10.73.0.0/16"}, CAID: ca.ID, CreatedAt: time.Now()}
	if err := st.CreateNetwork(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	item := &models.MeshImport{
		ID: "freeze-import", NetworkID: network.ID, CAID: ca.ID, OwnerOperatorID: op.ID,
		Status:         models.MeshImportStatusCollecting,
		TokenExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := st.CreateMeshImport(context.Background(), item, "nmi_freeze"); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		path     string
		csrfPath string
		form     url.Values
	}{
		{
			name: "host create", path: "/ui/hosts",
			form: url.Values{"network_id": {network.ID}, "name": {"new-host"}, "nebula_ips": {"10.73.0.10"}, "role": {"host"}},
		},
		{
			name: "network create", path: "/ui/networks",
			form: url.Values{"name": {"Another Network"}, "cidrs": {"10.74.0.0/16"}, "ca_id": {ca.ID}},
		},
		{name: "CA rotate", path: "/ui/cas/" + ca.ID + "/rotate", csrfPath: "/ui/cas/" + ca.ID, form: url.Values{}},
		{name: "CA retire", path: "/ui/cas/" + ca.ID + "/retire", csrfPath: "/ui/cas/" + ca.ID, form: url.Values{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			csrfPath := test.csrfPath
			if csrfPath == "" {
				csrfPath = test.path
			}
			csrfToken, cookies := getCSRFTokenFromCookies(t, w, csrfPath, []*http.Cookie{cookie})
			test.form.Set("_csrf", csrfToken)
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.form.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, current := range cookies {
				request.AddCookie(current)
			}
			response := httptest.NewRecorder()
			w.ServeHTTP(response, request)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestImportingHostWebMutationsReturnConflict(t *testing.T) {
	w, st := newTestWeb(t)
	cookies := loginSession(t, w)
	ca := seedActiveCA(t, st, "importing-host-ca", "admin-test-id", "Importing Host CA")
	network := &models.Network{
		ID: "importing-host-network", Name: "Importing Host Network",
		CIDRs: []string{"10.75.0.0/16"}, CAID: ca.ID, CreatedAt: time.Now(),
	}
	if err := st.CreateNetwork(context.Background(), network); err != nil {
		t.Fatal(err)
	}
	host := &models.Host{
		ID: "importing-host", NetworkID: network.ID, CAID: ca.ID, Name: "importing-host",
		NebulaIPs: []string{"10.75.0.10"}, Groups: []string{}, Role: models.HostRoleHost,
		Status: models.HostStatusImporting, Kind: models.HostKindAgent, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := st.CreateHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/ui/hosts/" + host.ID + "/edit", "name=changed"},
		{http.MethodPost, "/ui/hosts/" + host.ID + "/block", ""},
		{http.MethodPost, "/ui/hosts/" + host.ID + "/mobile-bundle/generate", ""},
		{http.MethodDelete, "/ui/hosts/" + host.ID, ""},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			csrfToken, requestCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/"+host.ID, cookies)
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("X-CSRF-Token", csrfToken)
			for _, cookie := range requestCookies {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()
			w.ServeHTTP(response, request)
			if response.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body = %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMeshImportWebPrefillsNetworkCIDRsFromCAConstraints(t *testing.T) {
	w, st := newTestWeb(t)
	ca := seedActiveCA(t, st, "constrained-ca", "admin-test-id", "Constrained CA")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate, err := (&cert.TBSCertificate{
		Version: cert.Version2, Name: "constrained-ca", IsCA: true,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		PublicKey: publicKey, Curve: cert.Curve_CURVE25519,
		Networks: []netip.Prefix{netip.MustParsePrefix("10.88.1.1/16"), netip.MustParsePrefix("fd88::1/64")},
	}).Sign(nil, cert.Curve_CURVE25519, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := certificate.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(context.Background(), `UPDATE cas SET cert_pem = ? WHERE id = ?`, string(certPEM), ca.ID); err != nil {
		t.Fatal(err)
	}

	cookies := loginSession(t, w)
	request := httptest.NewRequest(http.MethodGet, "/ui/networks?ca_id="+ca.ID, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	w.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`value="10.88.0.0/16"`, `value="fd88::/64"`, `value="` + ca.ID + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("network form missing %s", want)
		}
	}
}
