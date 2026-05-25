package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

const (
	sessionCookieName  = "nebula_session"
	sessionDuration    = 24 * time.Hour
	pendingTOTPMaxLife = 5 * time.Minute
)

// SessionManager handles DB-backed cookie sessions for operator users.
type SessionManager struct {
	store        store.Store
	cookieSecure bool

	// csrfRand is the entropy source for CSRF token rotation. Production
	// callers leave it at the default (rand.Reader). Tests substitute a
	// failing reader via SetCSRFRandForTest to exercise the fail-closed
	// rotation paths without a package-level var swap (no parallel-test
	// race when other web tests adopt t.Parallel()).
	csrfRand io.Reader
}

// NewSessionManager creates a new session manager backed by the given store.
func NewSessionManager(s store.Store) *SessionManager {
	return &SessionManager{store: s, csrfRand: rand.Reader}
}

// SetCSRFRandForTest swaps the CSRF entropy source on this SessionManager
// instance. Tests use this to inject a failing reader and pin the
// fail-closed rotation behavior; production callers never need it.
func (sm *SessionManager) SetCSRFRandForTest(r io.Reader) {
	sm.csrfRand = r
}

// SetCookieSecure controls the Secure attribute on session cookies. Called
// at startup from cli/serve.go with the resolved server-config value.
// Closes GHSA-rqfj-vv8r-xhqc.
func (sm *SessionManager) SetCookieSecure(secure bool) {
	sm.cookieSecure = secure
}

// LoginResult is the outcome of the first authentication step.
type LoginResult struct {
	Operator  *models.Operator
	NeedsTOTP bool
}

// Login looks up the operator by username, verifies the password (bcrypt),
// records a session, sets the cookie, and returns the operator. The second
// return value is false when the credentials were invalid. When the operator
// has TOTP enabled, the created session is in `pending_totp` state and the
// caller must complete authentication via FinishTOTP.
func (sm *SessionManager) Login(w http.ResponseWriter, r *http.Request, username, password string) (LoginResult, bool, error) {
	if username == "" || password == "" {
		return LoginResult{}, false, nil
	}
	op, err := sm.store.GetOperatorByUsername(r.Context(), username)
	if errors.Is(err, store.ErrNotFound) {
		return LoginResult{}, false, nil
	}
	if err != nil {
		return LoginResult{}, false, fmt.Errorf("lookup operator: %w", err)
	}
	if op.Status != models.OperatorStatusActive {
		return LoginResult{}, false, nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(password)); err != nil {
		// Wrong password is a normal auth failure (bool=false), not a system
		// error to surface to the caller.
		return LoginResult{}, false, nil //nolint:nilerr
	}

	// Generate both tokens BEFORE any DB write or response mutation.
	// A crypto/rand failure here must not leave a half-built session in
	// the DB or a stale CSRF cookie on the browser — see #144.
	token, err := generateToken()
	if err != nil {
		return LoginResult{}, false, fmt.Errorf("generate session token: %w", err)
	}
	csrfToken, err := generateCSRFToken(sm.csrfRand)
	if err != nil {
		return LoginResult{}, false, fmt.Errorf("generate csrf token: %w", err)
	}

	state := models.SessionStateAuthenticated
	expires := time.Now().Add(sessionDuration)
	cookieMaxAge := int(sessionDuration.Seconds())
	if op.TOTPEnabled {
		state = models.SessionStatePendingTOTP
		expires = time.Now().Add(pendingTOTPMaxLife)
		cookieMaxAge = int(pendingTOTPMaxLife.Seconds())
	}
	if err := sm.store.CreateOperatorSession(r.Context(), &models.OperatorSession{
		Token:      token,
		OperatorID: op.ID,
		State:      state,
		ExpiresAt:  expires,
	}); err != nil {
		return LoginResult{}, false, fmt.Errorf("create session: %w", err)
	}

	// Both tokens already generated above; only commit to the response
	// and the secondary last_login_at write now that the session row
	// is durable.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure gated by sm.cookieSecure, wired in serve.go from server config; verified by TestOIDC_SetCookieSecure
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   cookieMaxAge,
	})
	setCSRFCookie(w, csrfToken, sm.cookieSecure)
	if !op.TOTPEnabled {
		if err := sm.store.UpdateOperatorLastLogin(r.Context(), op.ID, time.Now()); err != nil {
			slog.Debug("update last login", "error", err)
		}
	}

	return LoginResult{Operator: op, NeedsTOTP: op.TOTPEnabled}, true, nil
}

// StartAuthenticatedSession creates a fully authenticated session for the
// given operator and sets the session cookie. Used by external login flows
// (e.g. OIDC) that have already verified the operator's identity.
func (sm *SessionManager) StartAuthenticatedSession(w http.ResponseWriter, r *http.Request, op *models.Operator) error {
	// Generate both tokens BEFORE any DB write or response mutation
	// so an entropy failure surfaces without partial side effects.
	// See Login for the rationale (#144).
	token, err := generateToken()
	if err != nil {
		return fmt.Errorf("generate session token: %w", err)
	}
	csrfToken, err := generateCSRFToken(sm.csrfRand)
	if err != nil {
		return fmt.Errorf("generate csrf token: %w", err)
	}

	expires := time.Now().Add(sessionDuration)
	if err := sm.store.CreateOperatorSession(r.Context(), &models.OperatorSession{
		Token:      token,
		OperatorID: op.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  expires,
	}); err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure gated by sm.cookieSecure, wired in serve.go from server config; verified by TestOIDC_SetCookieSecure
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	setCSRFCookie(w, csrfToken, sm.cookieSecure)
	if err := sm.store.UpdateOperatorLastLogin(r.Context(), op.ID, time.Now()); err != nil {
		slog.Debug("update last login", "error", err)
	}

	return nil
}

// PendingOperator returns the operator awaiting second-factor confirmation
// on the current session cookie, or nil if no pending session exists.
func (sm *SessionManager) PendingOperator(r *http.Request) *models.Operator {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	op, err := sm.store.GetPendingTwoFactorOperator(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}
	return op
}

// CompleteTwoFactor promotes the current pending session to fully
// authenticated, refreshes the cookie expiry, and updates last_login_at.
//
// On CSRF rotation entropy failure (#144), CompleteTwoFactor returns
// without promoting the session — the pending_totp row stays alive
// for its remaining TTL so the user can retry the second factor
// without re-entering the password.
func (sm *SessionManager) CompleteTwoFactor(w http.ResponseWriter, r *http.Request, operatorID string) error {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return fmt.Errorf("missing session cookie: %w", err)
	}

	// Generate the rotated CSRF token BEFORE promoting. An entropy
	// failure here must leave the pending session intact so the user
	// can retry the second factor — see #144 and the doc comment above.
	csrfToken, err := generateCSRFToken(sm.csrfRand)
	if err != nil {
		return fmt.Errorf("generate csrf token: %w", err)
	}

	newExpiry := time.Now().Add(sessionDuration)
	if err := sm.store.PromoteOperatorSession(r.Context(), cookie.Value, newExpiry); err != nil {
		return fmt.Errorf("promote session: %w", err)
	}

	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure gated by sm.cookieSecure, wired in serve.go from server config; verified by TestOIDC_SetCookieSecure
		Name:     sessionCookieName,
		Value:    cookie.Value,
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})
	setCSRFCookie(w, csrfToken, sm.cookieSecure)
	if err := sm.store.UpdateOperatorLastLogin(r.Context(), operatorID, time.Now()); err != nil {
		slog.Debug("update last login", "error", err)
	}

	return nil
}

// Logout invalidates the session cookie and removes the DB record.
func (sm *SessionManager) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		if err := sm.store.DeleteOperatorSession(r.Context(), cookie.Value); err != nil {
			slog.Debug("delete session", "error", err)
		}
	}
	// Match every attribute of the live session cookie so browsers reliably
	// replace it. RFC 6265 requires (Name, Domain, Path) to match; setting
	// SameSite and Secure to the same values prevents fingerprint mismatches
	// that have caused stale-cookie bugs in production CDNs.
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure gated by sm.cookieSecure, wired in serve.go from server config; verified by TestOIDC_SetCookieSecure
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   sm.cookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Clear CSRF cookie on logout
	clearCSRFCookie(w, sm.cookieSecure)
}

// CurrentOperator returns the operator owning the request's session cookie,
// or nil if there is no valid session. A disabled operator's session is also
// treated as invalid.
func (sm *SessionManager) CurrentOperator(r *http.Request) *models.Operator {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	op, err := sm.store.GetOperatorBySession(r.Context(), cookie.Value)
	if err != nil {
		return nil
	}
	return op
}

// IsAuthenticated reports whether the request carries a valid session.
func (sm *SessionManager) IsAuthenticated(r *http.Request) bool {
	return sm.CurrentOperator(r) != nil
}

// StartCleanup runs a background goroutine that periodically deletes expired
// sessions from the store. It stops when ctx is canceled.
func (sm *SessionManager) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := sm.store.DeleteExpiredOperatorSessions(ctx, time.Now()); err != nil {
					slog.Debug("cleanup expired sessions", "error", err)
				}
			}
		}
	}()
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
