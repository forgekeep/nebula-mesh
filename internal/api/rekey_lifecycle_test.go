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
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// pollForRekey performs one signed poll and returns the decoded response.
func pollForRekey(t *testing.T, srv *Server, agent enrolledAgent) agentUpdatesResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("poll: status %d, body %s", rec.Code, rec.Body.String())
	}
	var resp agentUpdatesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// enrollWithToken runs a full enrollment handshake with the given token,
// standing in for the agent's re-enrollment after a rekey.
func enrollWithToken(t *testing.T, srv *Server, token string) *httptest.ResponseRecorder {
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
	body, _ := json.Marshal(enrollRequest{
		Token:         token,
		PublicKeyPEM:  string(cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, x25519Pub)),
		SigningPubPEM: string(pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: edPub})),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewBuffer(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// TestRekey_ReofferedUntilEnrollmentCompletes is the regression test for a
// silently dropped rekey.
//
// The flag used to clear the moment the token was minted, so an agent that
// could not complete the re-enrollment — an unwritable directory, a crash, a
// host that never came back — lost the request outright: the server reported
// nothing pending while the host went on serving the certificate the rekey
// was meant to replace, and re-requesting it just repeated the cycle.
func TestRekey_ReofferedUntilEnrollmentCompletes(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	ctx := context.Background()

	host, err := st.GetHostByFingerprint(ctx, agent.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPendingRekey(ctx, host.ID); err != nil {
		t.Fatal(err)
	}

	// First poll: the agent is told to re-key but (as far as the server can
	// tell) never follows through.
	first := pollForRekey(t, srv, agent)
	if !first.RekeyRequired || first.EnrollmentToken == "" {
		t.Fatal("first poll did not carry the rekey signal")
	}

	// Second poll: the rekey must still be on offer.
	second := pollForRekey(t, srv, agent)
	if !second.RekeyRequired || second.EnrollmentToken == "" {
		t.Fatal("rekey was dropped after one unanswered poll — the host would keep its old certificate forever")
	}
	if second.EnrollmentToken == first.EnrollmentToken {
		t.Error("a re-offer must mint a fresh token; only the hash is stored, so the old one cannot be re-sent")
	}

	// The superseded token must be dead, so re-offering cannot leave a trail
	// of usable credentials behind it. (That only one row survives is pinned
	// in the store's TestCreateTokenForHost_SupersedesPreviousUnused.)
	if rec := enrollWithToken(t, srv, first.EnrollmentToken); rec.Code == http.StatusOK {
		t.Error("the superseded token still enrolled; re-offering must invalidate the one it replaces")
	}
}

// TestRekey_ClearedByCompletedEnrollment: the flag's one exit path. It clears
// in the same transaction as the certificate it asked for, so the host cannot
// end up enrolled-but-still-pending or pending-but-already-enrolled.
func TestRekey_ClearedByCompletedEnrollment(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	ctx := context.Background()

	host, err := st.GetHostByFingerprint(ctx, agent.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPendingRekey(ctx, host.ID); err != nil {
		t.Fatal(err)
	}

	resp := pollForRekey(t, srv, agent)
	if !resp.RekeyRequired {
		t.Fatal("poll did not carry the rekey signal")
	}

	if rec := enrollWithToken(t, srv, resp.EnrollmentToken); rec.Code != http.StatusOK {
		t.Fatalf("re-enroll: status %d, body %s", rec.Code, rec.Body.String())
	}

	got, err := st.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PendingRekey {
		t.Error("PendingRekey survived a completed enrollment; the agent would be told to re-key forever")
	}
}

// TestRekey_NotOfferedOnceCleared: with nothing pending, an ordinary poll must
// not hand out enrollment tokens.
func TestRekey_NotOfferedOnceCleared(t *testing.T) {
	srv, _ := newTestServer(t)
	agent := enrolledFixture(t, srv)

	resp := pollForRekey(t, srv, agent)
	if resp.RekeyRequired {
		t.Error("RekeyRequired set without a pending rekey")
	}
	if resp.EnrollmentToken != "" {
		t.Error("an enrollment token was minted for a host with no pending rekey")
	}
}
