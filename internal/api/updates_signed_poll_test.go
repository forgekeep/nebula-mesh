package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/models"
	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
)

// enrolledAgent represents a fully enrolled host fixture in the
// signed-poll test suite: cert fingerprint + Ed25519 signing keypair.
type enrolledAgent struct {
	fingerprint string
	signingPub  ed25519.PublicKey
	signingPriv ed25519.PrivateKey
}

// enrolledFixture creates a network + host and runs the full enrollment
// handshake (X25519 + Ed25519). The host row ends up with both
// `cert_fingerprint` and `signing_pub_pem` populated, so signed polls can
// be exercised end-to-end.
func enrolledFixture(t *testing.T, srv *Server) enrolledAgent {
	t.Helper()
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "signed-host",
		NebulaIPs: []string{"192.168.100.30"},
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

	// X25519 for the cert.
	x25519Priv := make([]byte, 32)
	if _, err := rand.Read(x25519Priv); err != nil {
		t.Fatal(err)
	}
	x25519Pub, err := curve25519.X25519(x25519Priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, x25519Pub)

	// Ed25519 for signed polls.
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingPubPEM := pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: edPub})

	enrollBody, _ := json.Marshal(enrollRequest{
		Token:         created.EnrollmentToken,
		PublicKeyPEM:  string(pubKeyPEM),
		SigningPubPEM: string(signingPubPEM),
	})
	er := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewBuffer(enrollBody))
	ew := httptest.NewRecorder()
	srv.ServeHTTP(ew, er)
	if ew.Code != http.StatusOK {
		t.Fatalf("enroll: %d / %s", ew.Code, ew.Body.String())
	}
	var enrolled struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	_ = json.NewDecoder(ew.Body).Decode(&enrolled)
	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(enrolled.CertificatePEM))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := hostCert.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return enrolledAgent{fingerprint: fp, signingPub: edPub, signingPriv: edPriv}
}

// signPoll mutates the request, attaching the four ADR 0004 headers.
func signPoll(t *testing.T, req *http.Request, agent enrolledAgent, opts ...func(*signOpts)) {
	t.Helper()
	o := signOpts{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	for _, f := range opts {
		f(&o)
	}
	if o.Nonce == "" {
		nb := make([]byte, 16)
		if _, err := rand.Read(nb); err != nil {
			t.Fatal(err)
		}
		o.Nonce = base64.StdEncoding.EncodeToString(nb)
	}
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	canonical := corepop.CanonicalString(req.Method, req.URL.Path, host, o.Timestamp, o.Nonce)
	if o.CanonicalOverride != "" {
		canonical = o.CanonicalOverride
	}
	priv := agent.signingPriv
	if o.PrivateKey != nil {
		priv = o.PrivateKey
	}
	sig := ed25519.Sign(priv, []byte(canonical))
	encoded := base64.StdEncoding.EncodeToString(sig)
	if o.SignatureOverride != "" {
		encoded = o.SignatureOverride
	}
	req.Header.Set(corepop.HeaderFingerprint, agent.fingerprint)
	req.Header.Set(corepop.HeaderTimestamp, o.Timestamp)
	req.Header.Set(corepop.HeaderNonce, o.Nonce)
	req.Header.Set(corepop.HeaderSignature, encoded)
}

type signOpts struct {
	Timestamp         string
	Nonce             string
	PrivateKey        ed25519.PrivateKey
	CanonicalOverride string
	SignatureOverride string
}

func withTimestamp(ts string) func(*signOpts) { return func(o *signOpts) { o.Timestamp = ts } }
func withNonce(n string) func(*signOpts)      { return func(o *signOpts) { o.Nonce = n } }
func withPrivateKey(k ed25519.PrivateKey) func(*signOpts) {
	return func(o *signOpts) { o.PrivateKey = k }
}

func errBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestPoll_RejectsMissingHeaders(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "missing_signature") {
		t.Errorf("body = %q, want missing_signature", w.Body.String())
	}
}

func TestPoll_RejectsUnknownFingerprint(t *testing.T) {
	srv, _ := newTestServer(t)
	agent := enrolledFixture(t, srv)
	// Swap fingerprint to an unknown value.
	bogus := enrolledAgent{fingerprint: "deadbeef", signingPub: agent.signingPub, signingPriv: agent.signingPriv}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, bogus)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unknown_fingerprint") {
		t.Errorf("body = %q, want unknown_fingerprint", w.Body.String())
	}
}

func TestPoll_RejectsBadSignature(t *testing.T) {
	srv, _ := newTestServer(t)
	agent := enrolledFixture(t, srv)
	// Sign with a different keypair.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent, withPrivateKey(otherPriv))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "bad_signature") {
		t.Errorf("body = %q, want bad_signature", w.Body.String())
	}
}

func TestPoll_RejectsSkewedTimestamp(t *testing.T) {
	srv, _ := newTestServer(t)
	agent := enrolledFixture(t, srv)
	// 10 minutes in the past — outside ±5 min window.
	past := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent, withTimestamp(past))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "timestamp_skew") {
		t.Errorf("body = %q, want timestamp_skew", w.Body.String())
	}
}

func TestPoll_RejectsReplayedNonce(t *testing.T) {
	srv, _ := newTestServer(t)
	agent := enrolledFixture(t, srv)

	nonce := "fixed-nonce-12345678"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
		signPoll(t, req, agent, withNonce(nonce))
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if i == 0 && w.Code != http.StatusOK {
			t.Fatalf("first poll status = %d, want 200, body = %s", w.Code, w.Body.String())
		}
		if i == 1 {
			if w.Code != http.StatusUnauthorized {
				t.Errorf("second poll status = %d, want 401, body = %s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "replayed_nonce") {
				t.Errorf("body = %q, want replayed_nonce", w.Body.String())
			}
		}
	}
}

func TestPoll_HappyPath(t *testing.T) {
	srv, _ := newTestServer(t)
	agent := enrolledFixture(t, srv)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp agentUpdatesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Blocklist == nil {
		t.Error("blocklist nil; expected at least empty slice")
	}
}

// keep models import meaningful — used elsewhere by future PRs.
var _ = models.HostStatusEnrolled
var _ = errBody
