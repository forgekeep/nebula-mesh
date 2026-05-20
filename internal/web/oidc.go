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
	"github.com/juev/nebula-mesh/internal/config"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
	"golang.org/x/oauth2"
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
	_ = o.store.AddAuditEntry(r.Context(), op.Username, "operator.oidc.login", op.ID, issuer)

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
	o.states[state] = time.Now().Add(oidcStateTTL)
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
