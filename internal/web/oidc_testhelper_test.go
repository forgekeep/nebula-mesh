package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// mockIDP is an httptest-backed OpenID Connect identity provider that lets
// tests drive the full nebula-mesh OIDC callback flow without a real IdP.
//
// Modeled on dexidp/dex's connector/oidc/oidc_test.go:setupServer pattern
// (the 85-line idiom referenced in docs/nebula-mesh testing roadmap).
// Serves the four documents the relying-party flow needs:
//
//	GET  /.well-known/openid-configuration
//	GET  /keys                    (JWKS)
//	GET  /auth                    (authorization endpoint — opaque, never hit
//	                               by HandleCallback; we exchange tokens directly)
//	POST /token                   (returns a freshly-minted id_token whose
//	                               claims come from the last NextIDToken call)
//	GET  /userinfo                (echoes the same claims)
//
// Tests configure per-callback behavior with NextIDToken and (optionally)
// NextTokenResponse, then drive HandleCallback by issuing a request with
// the matching state cookie + state query parameter.
type mockIDP struct {
	server *httptest.Server

	signer    jose.Signer
	publicKey *rsa.PublicKey
	kid       string

	mu sync.Mutex
	// nextClaims is the claim set used by the next /token call. Tests set
	// this before driving HandleCallback. Defaults to a minimal valid token
	// (sub, aud, iss, exp/nbf, iat) so unset-claim tests are explicit.
	nextClaims map[string]any
	// rawTokenOverride, if non-empty, is returned verbatim as the id_token
	// instead of minting one from nextClaims. Use for malformed-token tests
	// (non-string id_token, wrong-aud token, wrong-iss token).
	rawTokenOverride string
	// tokenStatus, if non-zero, overrides the /token response status code
	// (200 default). Use for failed-exchange tests.
	tokenStatus int
}

// newMockIDP builds a mock IdP (signing key + handlers) without starting a
// server, so callers can choose a plaintext or TLS httptest server.
func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
		return nil
	}
	kid := "test-kid-1"
	signerKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key: jose.JSONWebKey{
			Key:       key,
			KeyID:     kid,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		},
	}
	signer, err := jose.NewSigner(signerKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
		return nil
	}

	return &mockIDP{
		signer:    signer,
		publicKey: &key.PublicKey,
		kid:       kid,
	}
}

// routes wires the five discovery/JWKS/token/userinfo/auth endpoints the
// relying-party flow needs onto a fresh mux.
func (m *mockIDP) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", m.handleDiscovery)
	mux.HandleFunc("/keys", m.handleJWKS)
	mux.HandleFunc("/auth", m.handleAuth)
	mux.HandleFunc("/token", m.handleToken)
	mux.HandleFunc("/userinfo", m.handleUserinfo)
	return mux
}

// setupOIDCServer starts a plaintext-HTTP mock IdP and returns a handle for
// configuring it. Callers must call t.Cleanup or defer Close.
func setupOIDCServer(t *testing.T) *mockIDP {
	t.Helper()
	idp := newMockIDP(t)
	idp.server = httptest.NewServer(idp.routes())
	t.Cleanup(idp.Close)
	return idp
}

// setupOIDCServerTLS starts the same mock IdP over TLS (self-signed cert), used
// to exercise oidc.tls_ca_cert certificate pinning (#264). The server's cert is
// reachable via idp.server.Certificate().
func setupOIDCServerTLS(t *testing.T) *mockIDP {
	t.Helper()
	idp := newMockIDP(t)
	idp.server = httptest.NewTLSServer(idp.routes())
	t.Cleanup(idp.Close)
	return idp
}

// Close stops the underlying httptest server.
func (m *mockIDP) Close() {
	if m.server != nil {
		m.server.Close()
	}
}

// Issuer returns the issuer URL (the base of the httptest server) so callers
// can wire it into config.OIDCConfig.Issuer.
func (m *mockIDP) Issuer() string { return m.server.URL }

// NextIDToken configures the claim set used by the next /token call. Returns
// the IDP so calls chain naturally with newOIDCFromMock.
func (m *mockIDP) NextIDToken(claims map[string]any) *mockIDP {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextClaims = claims
	m.rawTokenOverride = ""
	return m
}

// NextRawIDToken bypasses claim-based minting and returns the given string
// as the id_token in the next /token response. Used for malformed-token
// tests (wrong issuer, wrong audience, non-JWT garbage).
func (m *mockIDP) NextRawIDToken(raw string) *mockIDP {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rawTokenOverride = raw
	m.nextClaims = nil
	return m
}

// SetTokenStatus overrides the /token endpoint's response status code on the
// next call. Use 0 to reset to 200.
func (m *mockIDP) SetTokenStatus(status int) { //nolint:unused // reserved for future fail-path tests
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokenStatus = status
}

// mintToken signs the given claim map as an RS256 JWT using the IdP's signing
// key. Defaults exp/nbf/iat to sane values when the caller doesn't set them.
func (m *mockIDP) mintToken(claims map[string]any) (string, error) {
	now := time.Now()
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now.Unix()
	}
	if _, ok := claims["nbf"]; !ok {
		claims["nbf"] = now.Unix()
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now.Add(5 * time.Minute).Unix()
	}
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = m.server.URL
	}
	return jwt.Signed(m.signer).Claims(claims).Serialize()
}

func (m *mockIDP) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	doc := map[string]any{
		"issuer":                                m.server.URL,
		"authorization_endpoint":                m.server.URL + "/auth",
		"token_endpoint":                        m.server.URL + "/token",
		"jwks_uri":                              m.server.URL + "/keys",
		"userinfo_endpoint":                     m.server.URL + "/userinfo",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	}
	_ = json.NewEncoder(w).Encode(doc)
}

func (m *mockIDP) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	jwks := jwksDoc{
		Keys: []jwkEntry{{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: m.kid,
			N:   base64.RawURLEncoding.EncodeToString(m.publicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.publicKey.E)).Bytes()),
		}},
	}
	_ = json.NewEncoder(w).Encode(jwks)
}

func (m *mockIDP) handleAuth(w http.ResponseWriter, _ *http.Request) {
	// HandleCallback never hits /auth — the browser would. Return 200 so a
	// curl in the middle of debugging gets something useful.
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "mock idp auth endpoint")
}

func (m *mockIDP) handleToken(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	status := m.tokenStatus
	override := m.rawTokenOverride
	claims := m.nextClaims
	m.mu.Unlock()

	if status != 0 {
		w.WriteHeader(status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var idToken string
	if override != "" {
		idToken = override
	} else {
		if claims == nil {
			claims = map[string]any{}
		}
		tok, err := m.mintToken(claims)
		if err != nil {
			http.Error(w, "mint: "+err.Error(), http.StatusInternalServerError)
			return
		}
		idToken = tok
	}
	resp := map[string]any{
		"access_token": "mock-access-token",
		"token_type":   "Bearer",
		"id_token":     idToken,
		"expires_in":   300,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (m *mockIDP) handleUserinfo(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	claims := m.nextClaims
	m.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if claims == nil {
		claims = map[string]any{}
	}
	_ = json.NewEncoder(w).Encode(claims)
}

// jwksDoc / jwkEntry are the minimal shape the go-oidc verifier needs.
type jwksDoc struct {
	Keys []jwkEntry `json:"keys"`
}

type jwkEntry struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// newOIDCFromMock constructs an *OIDC wired to the given mock IdP. The
// returned OIDC has the same shape as production NewOIDC: it does discovery
// against the mock, attaches a verifier that enforces ClientID + issuer,
// and shares the same store-backed session manager as the rest of the test.
func newOIDCFromMock(t *testing.T, idp *mockIDP, s store.Store, extraCfg config.OIDCConfig) *OIDC {
	t.Helper()
	cfg := extraCfg
	cfg.Enabled = true
	cfg.Issuer = idp.Issuer()
	if cfg.ClientID == "" {
		cfg.ClientID = "test-client"
	}
	if cfg.ClientSecret == "" {
		cfg.ClientSecret = "test-secret"
	}
	if cfg.RedirectURL == "" {
		cfg.RedirectURL = "https://nebula-mesh.test/ui/oidc/callback"
	}
	sm := NewSessionManager(s)
	o, err := NewOIDC(context.Background(), &cfg, s, sm, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
		return nil
	}
	if o == nil {
		t.Fatal("NewOIDC returned nil")
		return nil
	}
	return o
}

// driveCallback issues a /ui/oidc/callback request with a valid state cookie
// and runs HandleCallback against it. Returns the recorder so tests can
// inspect status / body / Set-Cookie headers.
//
// stateValue is the value to put in BOTH the cookie and the ?state= query
// param. To exercise mismatch cases, pass different values via the *Mismatch
// variant or set the cookie / query explicitly in the test.
func driveCallback(t *testing.T, o *OIDC, stateValue, code string) *httptest.ResponseRecorder {
	t.Helper()
	// Pre-seat the state so consumeState recognizes it.
	o.rememberState(stateValue)
	q := "/ui/oidc/callback?state=" + stateValue
	if code != "" {
		q += "&code=" + code
	}
	req := httptest.NewRequest(http.MethodGet, q, nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: stateValue})
	rec := httptest.NewRecorder()
	o.HandleCallback(rec, req)
	return rec
}

// driveCallbackWithError exercises the IdP-error early-return branch: the
// IdP redirected back with ?error=...&state=... after the user denied
// consent (or some IdP-side failure). The state cookie is set so we can
// observe whether the early return invalidates the state.
func driveCallbackWithError(t *testing.T, o *OIDC, stateValue, errParam string) *httptest.ResponseRecorder { //nolint:unused // consumed by the state-error fix's regression test in a later commit
	t.Helper()
	o.rememberState(stateValue)
	q := "/ui/oidc/callback?error=" + errParam + "&state=" + stateValue
	req := httptest.NewRequest(http.MethodGet, q, nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: stateValue})
	rec := httptest.NewRecorder()
	o.HandleCallback(rec, req)
	return rec
}

// newOIDCForStateTests returns the minimum viable *OIDC for exercising the
// rememberState / consumeState / sweepLocked code paths without a real
// IdP, store, or session manager. State-sweep tests want to drive those
// methods directly; the full newOIDCFromMock path stands up an httptest
// server, generates an RSA key, and runs OIDC discovery, all of which are
// irrelevant to the in-memory map's behavior.
//
// Returns a struct with: empty states map, a discard-sink slog logger, an
// empty OIDCConfig, and zero values for the rest. Future required
// non-pointer fields show up here as a single edit rather than five
// scattered constructors across the sweep tests.
func newOIDCForStateTests(t *testing.T) *OIDC {
	t.Helper()
	return &OIDC{
		states: map[string]time.Time{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// hasState reports whether the in-memory states map currently carries the
// given token. Used by replay-defense assertions.
func (o *OIDC) hasState(state string) bool {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	_, ok := o.states[state]
	return ok
}

// stateCount returns the current size of the in-memory states map. Used by
// the TTL sweeper test.
func (o *OIDC) stateCount() int { //nolint:unused // consumed by the TTL sweeper fix's regression test in a later commit
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	return len(o.states)
}

// setStateExpiry rewrites a state entry's expiry to the given time without
// re-running rememberState. Reserved for future OIDC tests that need to
// plant already-expired entries without triggering the lazy sweep.
func (o *OIDC) setStateExpiry(state string, expiry time.Time) { //nolint:unused // reserved for future tests
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	o.states[state] = expiry
}

// findCallbackErrorBody pulls the first line of the response body, useful
// for matching against http.Error's "msg\n" output shape.
func findCallbackErrorBody(rec *httptest.ResponseRecorder) string { //nolint:unused // helper for future tests
	body := rec.Body.String()
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		return body[:i]
	}
	return body
}
