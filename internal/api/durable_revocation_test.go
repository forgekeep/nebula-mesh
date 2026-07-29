package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// SEC-PERSIST-001 / GHSA-339v-266x-79xr: certificate issuance must re-check durable revocation
// state (host blocked, owning operator disabled) at every signing path —
// enrollment, re-enrollment, and auto-renewal — not only at poll time.

// enrollKeyPEMs returns a fresh X25519 cert public key PEM and an Ed25519
// signing public key PEM, matching the agent's enrollment payload.
func enrollKeyPEMs(t *testing.T) (pubKeyPEM, signingPubPEM string) {
	t.Helper()
	x25519Priv := make([]byte, 32)
	if _, err := rand.Read(x25519Priv); err != nil {
		t.Fatal(err)
	}
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, x25519Pub)),
		string(pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: edPub}))
}

func createHostForEnroll(t *testing.T, srv *Server, netID, name, ip string) createHostResponse {
	t.Helper()
	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      name,
		NebulaIPs: []string{ip},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create host: %d / %s", w.Code, w.Body.String())
	}
	var resp createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func postEnroll(t *testing.T, srv *Server, token string) *httptest.ResponseRecorder {
	t.Helper()
	pub, signing := enrollKeyPEMs(t)
	body, _ := json.Marshal(enrollRequest{Token: token, PublicKeyPEM: pub, SigningPubPEM: signing})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// TestEnroll_BlockedHost_Denied is the core fix: a blocked host that obtains a
// fresh enrollment token must NOT be re-issued a certificate. Otherwise the
// blocklist (keyed by the old fingerprint) is silently bypassed on re-enroll.
func TestEnroll_BlockedHost_Denied(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	netID := createNetwork(t, srv)

	created := createHostForEnroll(t, srv, netID, "blocked-host", "192.168.100.50")

	// Enroll once so the host has a real cert + fingerprint.
	if w := postEnroll(t, srv, created.EnrollmentToken); w.Code != http.StatusOK {
		t.Fatalf("initial enroll: %d / %s", w.Code, w.Body.String())
	}

	// Block the host (adds its fingerprint to the blocklist, status=blocked).
	if _, err := st.BlockHostAndAddToBlocklist(ctx, created.Host.ID, "manual block"); err != nil {
		t.Fatal(err)
	}

	// Mint a fresh token directly (simulating the re-enroll path) and attempt to
	// re-enroll: this would previously succeed with a brand-new fingerprint.
	if err := st.CreateTokenForHost(ctx, created.Host.ID, "reenroll-token-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	w := postEnroll(t, srv, "reenroll-token-1")
	if w.Code != http.StatusForbidden {
		t.Fatalf("re-enroll of blocked host: status = %d, want 403; body = %s", w.Code, w.Body.String())
	}

	// Host must remain blocked — no silent un-block.
	got, err := st.GetHost(ctx, created.Host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.HostStatusBlocked {
		t.Errorf("host status = %q, want blocked", got.Status)
	}
}

// TestEnroll_DisabledOperator_Denied: a host whose owning operator has been
// disabled must not be able to enroll, even with a valid token.
func TestEnroll_DisabledOperator_Denied(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	netID := createNetwork(t, srv)

	created := createHostForEnroll(t, srv, netID, "orphan-host", "192.168.100.51")

	// Disable the operator that owns the default CA.
	if err := st.DisableOperator(ctx, "test-admin"); err != nil {
		t.Fatal(err)
	}

	w := postEnroll(t, srv, created.EnrollmentToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("enroll under disabled operator: status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}

// TestReenrollToken_BlockedHost_Refused: the re-enroll endpoint must not even
// mint a token for a blocked host (fail-fast at the operator action).
func TestReenrollToken_BlockedHost_Refused(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	netID := createNetwork(t, srv)

	created := createHostForEnroll(t, srv, netID, "blocked-reenroll", "192.168.100.52")
	if _, err := st.BlockHostAndAddToBlocklist(ctx, created.Host.ID, "manual block"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+created.Host.ID+"/reenroll", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("reenroll token for blocked host: status = %d, want 409; body = %s", w.Code, w.Body.String())
	}
}

// TestSignHostCert_DisabledOperator_Refused exercises the renewal path guard:
// signHostCert (used by auto-renewal and rotate-cert) must refuse to sign once
// the owning operator is disabled, so offboarding actually cuts off renewals.
func TestSignHostCert_DisabledOperator_Refused(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	netID := createNetwork(t, srv)

	created := createHostForEnroll(t, srv, netID, "renew-host", "192.168.100.53")
	if w := postEnroll(t, srv, created.EnrollmentToken); w.Code != http.StatusOK {
		t.Fatalf("initial enroll: %d / %s", w.Code, w.Body.String())
	}

	host, err := st.GetHost(ctx, created.Host.ID)
	if err != nil {
		t.Fatal(err)
	}
	certInfo, err := st.GetCertificateInfo(ctx, created.Host.ID)
	if err != nil {
		t.Fatal(err)
	}

	// While the operator is active, renewal signing succeeds.
	if _, err := srv.signHostCert(ctx, host, certInfo, time.Now()); err != nil {
		t.Fatalf("signHostCert with active operator: unexpected error: %v", err)
	}

	// Disable the operator; renewal signing must now be refused.
	if err := st.DisableOperator(ctx, "test-admin"); err != nil {
		t.Fatal(err)
	}
	_, err = srv.signHostCert(ctx, host, certInfo, time.Now())
	if !errors.Is(err, errOperatorDisabled) {
		t.Fatalf("signHostCert with disabled operator: err = %v, want errOperatorDisabled", err)
	}
}

// createMobileHost inserts a mobile host directly (the create-host API does not
// expose kind), mirroring mobile_bundle_test.go.
func createMobileHost(t *testing.T, srv *Server, st *store.SQLiteStore, netID, name, ip string, status models.HostStatus) string {
	t.Helper()
	now := time.Now()
	host := &models.Host{
		ID:        uuid.New().String(),
		NetworkID: netID,
		Name:      name,
		NebulaIPs: []string{ip},
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		Role:      models.HostRoleHost,
		Status:    status,
		CAID:      srv.defaultCAID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.CreateHost(context.Background(), host); err != nil {
		t.Fatalf("create mobile host: %v", err)
	}
	return host.ID
}

func postMobileBundle(t *testing.T, srv *Server, hostID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+hostID+"/mobile-bundle", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// TestMobileBundle_BlockedHost_Denied closes the bypass found in review: the
// mobile-bundle endpoint mints a fresh cert (new fingerprint) and must not do
// so for a blocked host, otherwise the fingerprint-keyed blocklist is sidestepped.
func TestMobileBundle_BlockedHost_Denied(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	netID := createNetwork(t, srv)

	hostID := createMobileHost(t, srv, st, netID, "iphone-blocked", "192.168.100.60", models.HostStatusEnrolled)
	if _, err := st.BlockHostAndAddToBlocklist(ctx, hostID, "manual block"); err != nil {
		t.Fatal(err)
	}

	if w := postMobileBundle(t, srv, hostID); w.Code != http.StatusForbidden {
		t.Fatalf("mobile-bundle for blocked host: status = %d, want 403; body = %s", w.Code, w.Body.String())
	}

	got, err := st.GetHost(ctx, hostID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.HostStatusBlocked {
		t.Errorf("host status = %q, want blocked", got.Status)
	}
}

const secondAdminKey = "second-admin-key-67890"

// seedSecondAdmin adds a second active admin operator with its own API key, so
// a caller can act after the default operator (test-admin) is disabled.
func seedSecondAdmin(t *testing.T, st *store.SQLiteStore) {
	t.Helper()
	ctx := context.Background()
	op := &models.Operator{
		ID:           "second-admin",
		Username:     "admin2",
		PasswordHash: "hash",
		Role:         "admin",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := st.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID:         "second-admin-key",
		OperatorID: op.ID,
		Name:       "second-admin-key",
	}, secondAdminKey); err != nil {
		t.Fatal(err)
	}
}

// TestMobileBundle_DisabledOperator_Denied: when the operator that owns a mobile
// host's CA is disabled, regenerating its bundle (a fresh cert) must be refused
// — even when an active admin makes the call. Proves the guard inspects the
// owning operator, not the caller.
func TestMobileBundle_DisabledOperator_Denied(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()
	netID := createNetwork(t, srv)
	seedSecondAdmin(t, st)

	// Host's CA is owned by test-admin (the default CA owner).
	hostID := createMobileHost(t, srv, st, netID, "iphone-orphan", "192.168.100.61", models.HostStatusPending)
	if err := st.DisableOperator(ctx, "test-admin"); err != nil {
		t.Fatal(err)
	}

	// Call as the still-active second admin (test-admin's own key is now revoked).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+hostID+"/mobile-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+secondAdminKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("mobile-bundle under disabled owner: status = %d, want 403; body = %s", w.Code, w.Body.String())
	}
}
