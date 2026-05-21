package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/juev/nebula-mesh/internal/config"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

const (
	oidcStateCookieName = "nebula_oidc_state"
	oidcStateTTL        = 10 * time.Minute
)

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

	stateMu sync.Mutex
	states  map[string]time.Time // state token → expiry

	// cookieSecure controls the Secure attribute on the OIDC state cookie.
	// Set via SetCookieSecure from the server's resolved config value.
	// Closes GHSA-rqfj-vv8r-xhqc.
	cookieSecure bool

	// provisionCA is invoked after a new operator is successfully created
	// during OIDC first-time login. Enables auto-provisioning of default CA
	// for user-role operators without coupling OIDC to Web struct.
	// If nil, auto-provision is skipped.
	provisionCA func(ctx context.Context, op *models.Operator) error
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
	return &OIDC{
		cfg:      *cfg,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		oauth:    oc,
		store:    s,
		session:  sm,
		logger:   logger,
		states:   make(map[string]time.Time),
	}, nil
}

// Enabled reports whether OIDC is configured.
func (o *OIDC) Enabled() bool { return o != nil }

// HandleLogin starts the OIDC authorization flow.
func (o *OIDC) HandleLogin(rw http.ResponseWriter, r *http.Request) {
	state, err := randomToken()
	if err != nil {
		o.logger.Error("oidc state", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	o.rememberState(state)
	http.SetCookie(rw, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   o.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oidcStateTTL.Seconds()),
	})
	http.Redirect(rw, r, o.oauth.AuthCodeURL(state), http.StatusSeeOther)
}

// HandleCallback completes the OIDC flow, upserts the local operator, and
// establishes a session cookie.
func (o *OIDC) HandleCallback(rw http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		// Consume the matching state before the early return so an
		// attacker who induces an IdP error on the first callback hit
		// cannot replay the same state on a follow-up callback with a
		// valid code. Missing-cookie / mismatched-state cases short-
		// circuit through the same code path: nothing was consumed, but
		// nothing was usable either.
		if cookie, err := r.Cookie(oidcStateCookieName); err == nil && cookie.Value != "" {
			if state := r.URL.Query().Get("state"); state != "" && cookie.Value == state {
				_ = o.consumeState(state)
			}
		}
		desc := r.URL.Query().Get("error_description")
		o.logger.Warn("oidc provider error", "error", errParam, "description", desc)
		http.Error(rw, "oidc provider error: "+errParam, http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(oidcStateCookieName)
	if err != nil || cookie.Value == "" || cookie.Value != state || !o.consumeState(state) {
		http.Error(rw, "invalid oidc state", http.StatusBadRequest)
		return
	}
	// Match every attribute of the live state cookie so the browser
	// replaces it reliably (RFC 6265). Without HttpOnly/SameSite/Secure
	// matching, some CDNs and corporate proxies keep the original around.
	http.SetCookie(rw, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   o.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(rw, "missing code", http.StatusBadRequest)
		return
	}

	tok, err := o.oauth.Exchange(r.Context(), code)
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
	idToken, err := o.verifier.Verify(r.Context(), rawID)
	if err != nil {
		http.Error(rw, "oidc id_token verification failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(rw, "oidc claims parse: "+err.Error(), http.StatusBadGateway)
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
		_ = o.store.AddAuditEntry(r.Context(), username, "operator.oidc.denied", subject, email)
		http.Error(rw, "your account is not allowed to log in", http.StatusForbidden)
		return
	}

	op, err := o.upsertOperator(r.Context(), issuer, subject, username, displayName)
	if err != nil {
		o.logger.Error("oidc upsert operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	details := issuer
	if emailUnverifiedAccepted {
		// Append rather than replace so existing queries against the
		// issuer URL keep working; new queries can match the suffix
		// `email_unverified_accepted=true` via a LIKE or substring
		// check. Mirrors the `predecessor=%s` / `new_key=true` key=val
		// shape used elsewhere in the audit log.
		details = fmt.Sprintf("%s email_unverified_accepted=true", issuer)
	}
	_ = o.store.AddAuditEntry(r.Context(), op.Username, "operator.oidc.login", op.ID, details)

	if err := o.session.StartAuthenticatedSession(rw, r, op); err != nil {
		o.logger.Error("oidc session", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
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
	op := &models.Operator{
		ID:           uuid.New().String(),
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: "oidc",
		AuthProvider: models.OperatorAuthOIDC,
		Role:         role,
		OIDCIssuer:   issuer,
		OIDCSubject:  subject,
	}
	if err := o.store.CreateOperator(ctx, op); err != nil {
		return nil, err
	}

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

func (o *OIDC) isAllowed(email string, groups []string) bool {
	if len(o.cfg.AllowedGroups) == 0 && len(o.cfg.AllowedEmails) == 0 {
		return true
	}
	for _, allowed := range o.cfg.AllowedEmails {
		if strings.EqualFold(allowed, email) {
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

func (o *OIDC) rememberState(state string) {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	o.sweepLocked(time.Now())
	o.states[state] = time.Now().Add(oidcStateTTL)
}

// sweepLocked drops every state entry whose expiry is at or before now. The
// caller MUST hold stateMu. Called lazily from rememberState so the per-call
// cost is amortised across logins and the map cannot grow without bound
// when an unauthenticated client bursts /ui/oidc/login. Avoiding a
// background goroutine keeps the OIDC type cheap to construct and matches
// the project's preference for lazy in-memory cleanup where the hot path
// already takes the lock.
func (o *OIDC) sweepLocked(now time.Time) {
	for s, exp := range o.states {
		if !now.Before(exp) {
			delete(o.states, s)
		}
	}
}

func (o *OIDC) consumeState(state string) bool {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	exp, ok := o.states[state]
	if !ok {
		return false
	}
	delete(o.states, state)
	return !time.Now().After(exp)
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

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
