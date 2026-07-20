package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

// enrollHost performs a minimal enrollment handshake and returns the response.
func enrollHost(t *testing.T, srv *Server, token string) *httptest.ResponseRecorder {
	t.Helper()
	x := make([]byte, 32)
	_, err := rand.Read(x)
	require.NoError(t, err)
	xPub, err := curve25519.X25519(x, curve25519.Basepoint)
	require.NoError(t, err)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	body, _ := json.Marshal(enrollRequest{
		Token:         token,
		PublicKeyPEM:  string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, xPub)),
		SigningPubPEM: string(pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: edPub})),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// TestEnroll_WritesAuditEntry verifies that a successful enrollment writes a
// host.enrolled audit entry with the certificate fingerprint (issue #292).
func TestEnroll_WritesAuditEntry(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	created := createHostForEvent(t, srv, netID)

	w := enrollHost(t, srv, created.EnrollmentToken)
	require.Equal(t, http.StatusOK, w.Code, "enroll: %d / %s", w.Code, w.Body.String())

	entries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: auditHostEnrolled,
		Limit:  10,
	})
	require.NoError(t, err)
	require.Len(t, entries, 1, "expected exactly one host.enrolled audit entry")
	require.Equal(t, created.Host.ID, entries[0].Resource)
	require.True(t, strings.HasPrefix(entries[0].Details, "fingerprint="),
		"audit details should contain fingerprint, got %q", entries[0].Details)
}

// TestEnroll_RekeyWritesRekeyAuditEntry verifies that enrollment completing a
// pending rekey writes host.rekey.completed instead of host.enrolled (#292).
func TestEnroll_RekeyWritesRekeyAuditEntry(t *testing.T) {
	srv, st := newTestServer(t)

	// Full enrollment via the signed-poll fixture.
	agent := enrolledFixture(t, srv)
	host, err := st.GetHostByFingerprint(context.Background(), agent.fingerprint)
	require.NoError(t, err)

	// Trigger a rekey: rotate-cert?new_key=true sets pending_rekey.
	rotReq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+host.ID+"/rotate-cert?new_key=true", nil)
	authRequest(rotReq)
	rotRec := httptest.NewRecorder()
	srv.ServeHTTP(rotRec, rotReq)
	require.Equal(t, http.StatusAccepted, rotRec.Code, "rotate-cert: %d / %s", rotRec.Code, rotRec.Body.String())

	// Confirm pending_rekey is set.
	host, err = st.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.True(t, host.PendingRekey, "host should have pending_rekey after rotate-cert new_key=true")

	// Mint a re-enroll token for the host.
	reReq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+host.ID+"/reenroll", nil)
	authRequest(reReq)
	reRec := httptest.NewRecorder()
	srv.ServeHTTP(reRec, reReq)
	require.Equal(t, http.StatusCreated, reRec.Code, "reenroll: %d / %s", reRec.Code, reRec.Body.String())

	var reResp struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.NewDecoder(reRec.Body).Decode(&reResp))
	require.NotEmpty(t, reResp.Token)

	// Second enrollment (rekey) with a fresh keypair.
	w2 := enrollHost(t, srv, reResp.Token)
	require.Equal(t, http.StatusOK, w2.Code, "rekey enroll: %d / %s", w2.Code, w2.Body.String())

	// Verify host.rekey.completed audit entry exists.
	rekeyEntries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: auditHostRekeyCompleted,
		Limit:  10,
	})
	require.NoError(t, err)
	require.Len(t, rekeyEntries, 1, "expected exactly one host.rekey.completed audit entry")
	require.Equal(t, host.ID, rekeyEntries[0].Resource)
	require.True(t, strings.HasPrefix(rekeyEntries[0].Details, "fingerprint="),
		"rekey audit details should contain fingerprint, got %q", rekeyEntries[0].Details)

	// Verify only one host.enrolled entry (from the initial enrollment).
	enrolledEntries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: auditHostEnrolled,
		Limit:  10,
	})
	require.NoError(t, err)
	require.Len(t, enrolledEntries, 1, "expected exactly one host.enrolled audit entry (initial only)")
}
