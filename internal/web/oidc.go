package web

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
	"uuid"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

const oidcHTTPTimeout = 10 * time.Second

// OIDC encapsulates the configured OpenID Connect identity provider and
// translates a successful callback into a local operator session.
type OIDC struct {
	cfg      config.OIDCConfig
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	store    store.Store
	session  *SessionManager
	logger   *slog.Logger

	flowCipher cipher.AEAD

	// cookieSecure controls the Secure attribute on the OIDC state cookie.
	// Set via SetCookieSecure from the server's resolved config value.
	// Closes GHSA-rqfj-vv8r-xhqc.
	cookieSecure bool

	// provisionCA is invoked after a new operator is successfully created
	// during OIDC first-time login. Enables auto-provisioning of default CA
	// for user-role operators without coupling OIDC to Web struct.
	// If nil, auto-provision is skipped.
	provisionCA func(ctx context.Context, op *models.Operator) error

	// httpClient is the bounded client used for every IdP request. When
	// oidc.tls_ca_cert is configured, its transport also pins that CA bundle.
	httpClient *http.Client
}

// SetCookieSecure controls the Secure attribute on the OIDC state cookie.
// Called at startup from cli/serve.go with the resolved server-config value.
func (o *OIDC) SetCookieSecure(secure bool) {
	if o == nil {
		return
	}
	o.cookieSecure = secure
}

// NewOIDC builds an OIDC integration from the given config. It contacts the
// issuer to fetch the OIDC discovery document. Returns (nil, nil) if OIDC is
// disabled or unconfigured.
func NewOIDC(ctx context.Context, cfg *config.OIDCConfig, s store.Store, sm *SessionManager, logger *slog.Logger) (*OIDC, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: issuer, client_id, redirect_url are required")
	}
	// Use one bounded client for discovery, JWKS retrieval and token exchange.
	// When tls_ca_cert is configured, the same client pins all IdP traffic to
	// that CA bundle (#264).
	httpClient, err := newOIDCHTTPClient(cfg.TLSCACert, oidcHTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}
	}
	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}
	flowCipher, err := newOIDCFlowCipher()
	if err != nil {
		return nil, fmt.Errorf("oidc flow cipher: %w", err)
	}
	return &OIDC{
		cfg:        *cfg,
		provider:   provider,
		verifier:   provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth:      oc,
		store:      s,
		session:    sm,
		logger:     logger,
		flowCipher: flowCipher,
		httpClient: httpClient,
	}, nil
}

// newOIDCHTTPClient builds the bounded client used for every IdP request. When
// caPath is set, the client trusts only that PEM CA bundle and fails rather than
// silently falling back to the system trust store.
func newOIDCHTTPClient(caPath string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("http timeout must be positive")
	}
	client := &http.Client{Timeout: timeout}
	if caPath == "" {
		return client, nil
	}
	pemBytes, err := os.ReadFile(caPath) // #nosec G304 -- operator-supplied trusted config path
	if err != nil {
		return nil, fmt.Errorf("read tls_ca_cert %q: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("tls_ca_cert %q: no valid PEM certificates", caPath)
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}
	return client, nil
}

// Enabled reports whether OIDC is configured.
func (o *OIDC) Enabled() bool { return o != nil }

// HandleLogin starts the OIDC authorization flow.
func (o *OIDC) HandleLogin(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	flow, err := newOIDCFlow(time.Now())
	if err != nil {
		o.logger.Error("oidc flow", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	sealed, err := o.sealFlow(flow)
	if err != nil {
		o.logger.Error("oidc flow cookie", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	o.setFlowCookie(rw, sealed, int(oidcFlowTTL.Seconds()))
	authURL := o.oauth.AuthCodeURL(flow.State, oauth2.S256ChallengeOption(flow.Verifier), oidc.Nonce(flow.Nonce))
	http.Redirect(rw, r, authURL, http.StatusSeeOther)
}

// HandleCallback completes the OIDC flow, upserts the local operator, and
// establishes a session cookie.
func (o *OIDC) HandleCallback(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Cache-Control", "no-store")
	query := r.URL.Query()
	flow, err := o.readFlow(r, query.Get("state"), time.Now())
	if err != nil {
		http.Error(rw, "invalid oidc state", http.StatusBadRequest)
		return
	}
	o.setFlowCookie(rw, "", -1)
	if query.Get("error") != "" {
		o.logger.Warn("oidc provider rejected login")
		http.Error(rw, "oidc login failed", http.StatusBadRequest)
		return
	}

	code := query.Get("code")
	if code == "" {
		http.Error(rw, "missing code", http.StatusBadRequest)
		return
	}

	// Route token exchange and id_token verification through the same bounded
	// client used for discovery and JWKS retrieval.
	ctx := oidc.ClientContext(r.Context(), o.httpClient)
	tok, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		o.logger.Error("oidc exchange", "error", err)
		http.Error(rw, "oidc token exchange failed", http.StatusBadGateway)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		http.Error(rw, "oidc response missing id_token", http.StatusBadGateway)
		return
	}
	idToken, err := o.verifier.Verify(ctx, rawID)
	if err != nil {
		o.logger.Error("oidc id_token verification failed", "error", err)
		http.Error(rw, "oidc verification failed", http.StatusBadGateway)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(flow.Nonce)) != 1 {
		http.Error(rw, "invalid oidc nonce", http.StatusBadRequest)
		return
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		o.logger.Error("oidc claims parse failed", "error", err)
		http.Error(rw, "oidc verification failed", http.StatusBadGateway)
		return
	}

	usernameClaim := o.cfg.UsernameClaim
	if usernameClaim == "" {
		usernameClaim = "preferred_username"
	}
	nameClaim := o.cfg.NameClaim
	if nameClaim == "" {
		nameClaim = "name"
	}
	groupsClaim := o.cfg.GroupsClaim
	if groupsClaim == "" {
		groupsClaim = "groups"
	}

	username, _ := claims[usernameClaim].(string)
	if username == "" {
		if sub, ok := claims["sub"].(string); ok {
			username = sub
		}
	}
	if username == "" {
		http.Error(rw, "oidc id_token missing username claim", http.StatusBadGateway)
		return
	}
	displayName, _ := claims[nameClaim].(string)
	email, _ := claims["email"].(string)
	subject := idToken.Subject
	issuer := idToken.Issuer

	// If the IdP supplied an email claim, refuse to consume it unless the
	// IdP also asserts the address is verified. Default-deny when
	// `email_verified` is missing or false: an attacker who registers an
	// unverified address at a permitted domain on the IdP would otherwise
	// satisfy AllowedEmails. Matches dex's connector posture; go-oidc does
	// not enforce this claim itself.
	//
	// Operators can disable the check entirely via
	// oidc.require_email_verified: false — the escape hatch for legacy
	// IdPs whose claim encoding parseEmailVerified can't decode. The
	// bypass is not silent: a per-login audit row tags the success path
	// with `email_unverified_accepted=true` so forensics can distinguish
	// bypass logins from verified ones via a single grep against the
	// existing `operator.oidc.login` action. Startup also emits a WARN
	// log surfacing the relaxed posture.
	emailUnverifiedAccepted := false
	if email != "" {
		if o.cfg.EmailVerifiedRequired() {
			if !parseEmailVerified(claims["email_verified"]) {
				_ = o.store.AddAuditEntry(r.Context(), username, "operator.oidc.denied", subject, "email_unverified")
				http.Error(rw, "your account is not allowed to log in", http.StatusForbidden)
				return
			}
		} else if !parseEmailVerified(claims["email_verified"]) {
			// The check is disabled AND the claim would not have
			// passed it. Tag the audit row so a bypass-login is
			// distinguishable from a verified-and-passed login.
			emailUnverifiedAccepted = true
		}
	}

	if !o.isAllowed(email, extractGroups(claims, groupsClaim)) {
		if o.confirmedGroupLoss(idToken, claims, groupsClaim, email) {
			if err := o.store.RevokeOIDCOperator(r.Context(), issuer, subject, nil); err != nil {
				o.logger.Error("oidc revoke denied identity", "error", err)
				http.Error(rw, "internal error", http.StatusInternalServerError)
				return
			}
		}
		_ = o.store.AddAuditEntry(r.Context(), username, "operator.oidc.denied", subject, email)
		http.Error(rw, "your account is not allowed to log in", http.StatusForbidden)
		return
	}

	// Record only verified, eligible callbacks. An anonymous start or a
	// rejected proof never consumes shared storage.
	if err := o.store.ConsumeOIDCLoginState(r.Context(), sha256.Sum256([]byte(flow.State)), flow.ExpiresAt); err != nil {
		if errors.Is(err, store.ErrReplayedNonce) {
			http.Error(rw, "invalid oidc state", http.StatusBadRequest)
			return
		}
		o.logger.Error("oidc consume flow", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	op, err := o.upsertOperator(r.Context(), issuer, subject, username, displayName)
	if err != nil {
		o.logger.Error("oidc upsert operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if op.Status != models.OperatorStatusActive {
		_ = o.store.AddAuditEntry(r.Context(), username, "operator.oidc.denied", subject, "operator_disabled")
		http.Error(rw, "your account is not allowed to log in", http.StatusForbidden)
		return
	}
	// Compute details once so the failure-branch audit row carries
	// the same `email_unverified_accepted=true` marker as the success
	// row — forensics for bypass-logins shouldn't drop a request just
	// because the session step errored.
	details := issuer
	if emailUnverifiedAccepted {
		// Append rather than replace so existing queries against the
		// issuer URL keep working; new queries can match the suffix
		// `email_unverified_accepted=true` via a LIKE or substring
		// check. Mirrors the `predecessor=%s` / `new_key=true` key=val
		// shape used elsewhere in the audit log.
		details = fmt.Sprintf("%s email_unverified_accepted=true", issuer)
	}

	if err := o.session.StartAuthenticatedSession(rw, r, op); err != nil {
		// Audit the failure so forensics can distinguish a rejected
		// or errored OIDC login from a verified-and-promoted one;
		// the success-side `operator.oidc.login` row is only written
		// below, after the session has actually been promoted.
		_ = o.store.AddAuditEntry(r.Context(), op.Username, "operator.oidc.session_failed", op.ID, details)
		o.logger.Error("oidc session", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	_ = o.store.AddAuditEntry(r.Context(), op.Username, "operator.oidc.login", op.ID, details)
	http.Redirect(rw, r, "/ui/", http.StatusSeeOther)
}

func (o *OIDC) upsertOperator(ctx context.Context, issuer, subject, username, displayName string) (*models.Operator, error) {
	if op, err := o.store.GetOperatorByOIDC(ctx, issuer, subject); err == nil {
		return op, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// config.OIDCConfig.Validate refuses the unset+no-allowlist combo at
	// startup; the remaining unset case has an allowlist gating who reaches
	// this branch, so "user" is the conservative default rather than the
	// prior implicit "admin".
	role := o.cfg.DefaultRole
	if role == "" {
		role = "user"
	}
	var createErr error
	for attempt := 0; attempt < 5; attempt++ {
		op := &models.Operator{
			ID:           uuid.NewV4().String(),
			Username:     username,
			DisplayName:  displayName,
			PasswordHash: "oidc",
			AuthProvider: models.OperatorAuthOIDC,
			Role:         role,
			OIDCIssuer:   issuer,
			OIDCSubject:  subject,
		}
		if attempt > 0 {
			op.Username = username + "-" + uuid.NewV4().String()
		}
		createErr = o.store.CreateOperator(ctx, op)
		if createErr == nil {
			// Attempt auto-provisioning of a default CA if wired (via WithOIDC).
			// This enables user-role operators to work with networks immediately
			// after first login, without explicit CA creation.
			// Errors are logged but do not block operator creation.
			if o.provisionCA != nil {
				if err := o.provisionCA(ctx, op); err != nil {
					o.logger.Warn("auto-provision default CA on OIDC login failed", "operator", op.Username, "error", err)
				}
			}
			return op, nil
		}

		if op, err := o.store.GetOperatorByOIDC(ctx, issuer, subject); err == nil {
			return op, nil
		} else if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		_, err := o.store.GetOperatorByUsername(ctx, op.Username)
		if err == nil {
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		return nil, createErr
	}
	return nil, fmt.Errorf("create OIDC operator after username collisions: %w", createErr)
}

func emailAllowlistMatches(allowed, email string) bool {
	if isASCII(allowed) && isASCII(email) {
		return strings.EqualFold(allowed, email)
	}
	return allowed == email
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func (o *OIDC) isAllowed(email string, groups []string) bool {
	if len(o.cfg.AllowedGroups) == 0 && len(o.cfg.AllowedEmails) == 0 {
		return true
	}
	for _, allowed := range o.cfg.AllowedEmails {
		if emailAllowlistMatches(allowed, email) {
			return true
		}
	}
	for _, allowed := range o.cfg.AllowedGroups {
		for _, g := range groups {
			if allowed == g {
				return true
			}
		}
	}
	return false
}

// parseEmailVerified decodes the OIDC `email_verified` claim across the
// shapes real-world IdPs send. The spec (OIDC core, section 5.1) calls
// for a JSON boolean, but Azure AD, Salesforce, older Keycloak releases
// and some SAML→OIDC gateways send a JSON string ("true"/"false"). A
// bare bool-typed type assertion fails closed for those callers,
// pressuring operators to disable the check entirely — worse outcome
// than accepting the documented string form.
//
// Accepted:
//   - bool true / bool false
//   - string "true" / "false" (case-insensitive: "True", "TRUE", etc.)
//
// Default-deny for everything else (nil, missing, numeric 0/1, nested
// object). Numeric encoding was raised during review but is rarer than
// the string form and violates the spec more clearly; rejecting it
// keeps the parser narrow.
//
// The strict posture is load-bearing and intentional:
//   - no whitespace trimming (" true " is rejected)
//   - no numeric coercion (1, 1.0, json.Number("1") all rejected — note
//     that encoding/json decodes JSON numbers as float64 by default, so
//     production callers see float64 not int)
//   - no "yes"/"no"/"on"/"off"/"1"/"0" string forms
//
// Widening the parser is a security-sensitive change: every new accepted
// shape is a new opportunity for an attacker-controlled IdP to satisfy
// the check with an unverified address. Operators who genuinely need
// looser handling should set oidc.require_email_verified: false as a
// deliberate opt-out (the bypass is logged at startup and audited per
// login).
func parseEmailVerified(raw any) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(v) {
		case "true":
			return true
		case "false":
			return false
		}
	}
	return false
}

func extractGroups(claims map[string]any, key string) []string {
	raw, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.Split(v, ",")
	}
	return nil
}
