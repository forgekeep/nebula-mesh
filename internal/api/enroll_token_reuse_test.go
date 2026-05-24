package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// TestEnroll_ReplayedToken_Returns409 exercises the enrollment-atomicity fix at
// the HTTP layer: once a token has enrolled a host it cannot be replayed. The
// first enroll succeeds (200); replaying the identical request returns 409
// "enrollment token already used" — here via the GetEnrollmentToken peek, which
// sees used=1. The concurrent variant (two requests both pass the peek, then the
// ConsumeTokenAndEnrollHost CAS lets exactly one win) is pinned at the store
// level by TestConsumeTokenAndEnrollHost_ConcurrentSameToken_ExactlyOneEnrolls.
func TestEnroll_ReplayedToken_Returns409(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "replay-host",
		NebulaIPs: []string{"192.168.100.40"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create host: %d / %s", w.Code, w.Body.String())
	}
	var created createHostResponse
	_ = json.NewDecoder(w.Body).Decode(&created)

	// A valid enroll request: X25519 cert key + Ed25519 signing key.
	x25519Priv := make([]byte, 32)
	if _, err := rand.Read(x25519Priv); err != nil {
		t.Fatal(err)
	}
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, x25519Pub)
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPubPEM := pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: edPub})

	enrollBody, _ := json.Marshal(enrollRequest{
		Token:         created.EnrollmentToken,
		PublicKeyPEM:  string(pubKeyPEM),
		SigningPubPEM: string(signingPubPEM),
	})

	// First enrollment succeeds.
	first := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewBuffer(enrollBody))
	fw := httptest.NewRecorder()
	srv.ServeHTTP(fw, first)
	if fw.Code != http.StatusOK {
		t.Fatalf("first enroll: %d / %s", fw.Code, fw.Body.String())
	}

	// Replaying the same token is rejected as already-used — not burned silently,
	// not re-issued.
	second := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewBuffer(enrollBody))
	sw := httptest.NewRecorder()
	srv.ServeHTTP(sw, second)
	if sw.Code != http.StatusConflict {
		t.Fatalf("replayed enroll: %d / %s, want 409", sw.Code, sw.Body.String())
	}
}
