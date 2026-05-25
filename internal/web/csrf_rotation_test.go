package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestCSRF_RotateOnLogin verifies that Login generates a fresh CSRF token
// and sets it in the response.
func TestCSRF_RotateOnLogin(t *testing.T) {
	w, store := newTestWeb(t)

	// Create an operator with the test password hash
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, store.CreateOperator(context.Background(), &models.Operator{
		ID:           "test-operator",
		Username:     "logintest",
		PasswordHash: string(hash),
		Status:       models.OperatorStatusActive,
	}))

	// First, make a GET request to /ui/login to establish initial CSRF cookie
	getReq := httptest.NewRequest(http.MethodGet, "/ui/login", nil)
	getRec := httptest.NewRecorder()
	w.ServeHTTP(getRec, getReq)

	var initialCSRF string
	for _, cookie := range getRec.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			initialCSRF = cookie.Value
			break
		}
	}
	require.NotEmpty(t, initialCSRF, "GET /ui/login should set CSRF cookie")

	// Now make a POST login request with the initial CSRF token
	form := url.Values{
		"username":    {"logintest"},
		"password":    {testPassword},
		csrfFormField: {initialCSRF},
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add the initial CSRF cookie to the request
	loginReq.AddCookie(&http.Cookie{
		Name:  csrfCookieName,
		Value: initialCSRF,
	})

	loginRec := httptest.NewRecorder()
	w.ServeHTTP(loginRec, loginReq)

	// Extract CSRF cookie from login response
	var newCSRFValue string
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			newCSRFValue = cookie.Value
			break
		}
	}

	// Verify that a CSRF token was set in the response
	assert.NotEmpty(t, newCSRFValue, "Login should set a CSRF cookie")
	// Verify it's a valid token (non-empty, hex-encoded 32-byte value = 64 chars)
	assert.Len(t, newCSRFValue, 64, "CSRF token should be 32 bytes hex-encoded")
	// Verify rotation: new token should differ from initial
	assert.NotEqual(t, initialCSRF, newCSRFValue, "Login should rotate CSRF token")

	// Rotation invariant: a form rendered before Login (carrying initialCSRF)
	// must not validate against the post-rotation cookie.
	assertPreRotationTokenRejected(t, w, initialCSRF, newCSRFValue)
}

// TestCSRF_RotateOnOIDCSession verifies that StartAuthenticatedSession
// generates a fresh CSRF token.
func TestCSRF_RotateOnOIDCSession(t *testing.T) {
	w, store := newTestWeb(t)
	op := &models.Operator{
		ID:       "oidc-op",
		Username: "oidc-user",
		Status:   models.OperatorStatusActive,
		// Don't require password_hash for OIDC operators
	}
	// For OIDC operators, we need to allow missing password_hash
	// Actually, let's check what the store requires
	err := store.CreateOperator(context.Background(), op)
	if err != nil {
		// If password_hash is required, we can either set it to empty string
		// or skip this test. For now, let's set a dummy hash.
		op.PasswordHash = "$2a$12$abcdefghijklmnopqrstuvwxyzABCDEF"
		err = store.CreateOperator(context.Background(), op)
	}
	require.NoError(t, err)

	// Establish a pre-rotation CSRF cookie via GET (simulates the browser
	// having visited the login page before bouncing through OIDC).
	getReq := httptest.NewRequest(http.MethodGet, "/ui/login", nil)
	getRec := httptest.NewRecorder()
	w.ServeHTTP(getRec, getReq)
	var initialCSRF string
	for _, cookie := range getRec.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			initialCSRF = cookie.Value
			break
		}
	}
	require.NotEmpty(t, initialCSRF, "GET /ui/login should set CSRF cookie")

	// Simulate OIDC callback by calling StartAuthenticatedSession directly
	sessionReq := httptest.NewRequest(http.MethodGet, "/ui/callback", nil)
	sessionRec := httptest.NewRecorder()
	err = w.session.StartAuthenticatedSession(sessionRec, sessionReq, op)
	require.NoError(t, err)

	// Extract CSRF cookie from OIDC response
	var newCSRF string
	for _, cookie := range sessionRec.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			newCSRF = cookie.Value
			break
		}
	}

	assert.NotEmpty(t, newCSRF, "StartAuthenticatedSession should set CSRF cookie")
	assert.Len(t, newCSRF, 64, "CSRF token should be 32 bytes hex-encoded")
	assert.NotEqual(t, initialCSRF, newCSRF, "StartAuthenticatedSession should rotate CSRF token")

	// Rotation invariant: a form rendered before OIDC completion (carrying
	// initialCSRF) must not validate against the post-rotation cookie.
	assertPreRotationTokenRejected(t, w, initialCSRF, newCSRF)
}

// TestCSRF_RotateOnTOTP verifies that CompleteTwoFactor generates a fresh
// CSRF token when promoting pending_totp to authenticated.
func TestCSRF_RotateOnTOTP(t *testing.T) {
	w, store := newTestWeb(t)

	// Fetch the admin operator that newTestWeb creates (testUsername with testPassword)
	op, err := store.GetOperatorByUsername(context.Background(), testUsername)
	require.NoError(t, err)

	// Enable TOTP on this operator
	op.TOTPEnabled = true
	// (There's no UpdateOperator method easily available, so we'll skip this
	// test with a simplified approach: just verify that CompleteTwoFactor
	// rotates the token when called directly)

	// Get initial CSRF by making a GET request
	getReq := httptest.NewRequest(http.MethodGet, "/ui/login", nil)
	getRec := httptest.NewRecorder()
	w.ServeHTTP(getRec, getReq)

	var initialCSRF string
	for _, cookie := range getRec.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			initialCSRF = cookie.Value
			break
		}
	}

	// Create a session manually for testing (simulating pending TOTP state)
	// Use a dummy session token (can be any string)
	sessionToken := "dummy-session-token-for-testing"
	sess := &models.OperatorSession{
		Token:      sessionToken,
		OperatorID: op.ID,
		State:      models.SessionStatePendingTOTP,
	}
	require.NoError(t, store.CreateOperatorSession(context.Background(), sess))

	// Extract CSRF before TOTP completion (we'd get this from a login request,
	// but for simplicity, use the one from GET)
	preTOTPCSRF := initialCSRF

	// Now complete TOTP by calling CompleteTwoFactor with the session
	totpReq := httptest.NewRequest(http.MethodPost, "/ui/login/totp", nil)
	totpReq.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionToken,
	})
	totpRec := httptest.NewRecorder()
	err = w.session.CompleteTwoFactor(totpRec, totpReq, op.ID)
	require.NoError(t, err)

	// Extract CSRF from TOTP completion
	var postTOTPCSRF string
	for _, cookie := range totpRec.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			postTOTPCSRF = cookie.Value
			break
		}
	}

	assert.NotEmpty(t, postTOTPCSRF, "CompleteTwoFactor should set CSRF cookie")
	assert.Len(t, postTOTPCSRF, 64, "CSRF token should be 32 bytes hex-encoded")
	// Verify rotation: tokens should differ (very likely with random generation)
	if preTOTPCSRF != "" {
		assert.NotEqual(t, preTOTPCSRF, postTOTPCSRF, "TOTP completion should rotate CSRF token")

		// Rotation invariant: a form rendered before TOTP completion
		// (carrying preTOTPCSRF) must not validate against the
		// post-rotation cookie.
		assertPreRotationTokenRejected(t, w, preTOTPCSRF, postTOTPCSRF)
	}
}

// TestCSRF_ClearOnLogout verifies that Logout clears the CSRF cookie
// by setting MaxAge=-1.
func TestCSRF_ClearOnLogout(t *testing.T) {
	w, _ := newTestWeb(t)

	// Create a logged-in session using loginSession helper
	cookies := loginSession(t, w)
	require.NotEmpty(t, cookies, "loginSession should return cookies")

	// Verify that we have a CSRF cookie before logout
	var csrfCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == csrfCookieName {
			csrfCookie = cookie
			break
		}
	}
	require.NotNil(t, csrfCookie, "loginSession should include CSRF cookie")

	// Now logout
	logoutReq := httptest.NewRequest(http.MethodPost, "/ui/logout", nil)
	for _, cookie := range cookies {
		logoutReq.AddCookie(cookie)
	}
	logoutRec := httptest.NewRecorder()
	w.session.Logout(logoutRec, logoutReq)

	// Check that response contains CSRF cookie with MaxAge<0
	var logoutCSRF *http.Cookie
	for _, cookie := range logoutRec.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			logoutCSRF = cookie
			break
		}
	}

	assert.NotNil(t, logoutCSRF, "Logout should clear CSRF cookie")
	assert.Equal(t, -1, logoutCSRF.MaxAge, "Logout should set CSRF cookie MaxAge=-1")
}

// assertPreRotationTokenRejected verifies that a form-token issued before
// rotation no longer validates against the post-rotation cookie. Pins the
// rotation invariant from both sides: just observing that the new cookie
// differs from the old is not enough — a regression that emitted a new
// cookie while still accepting the pre-rotation form-token would pass.
func assertPreRotationTokenRejected(t *testing.T, w *Web, preRotationToken, postRotationCookie string) {
	t.Helper()
	form := url.Values{csrfFormField: {preRotationToken}}
	req := httptest.NewRequest(http.MethodPost, "/ui/cas/ca-id/delete",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: postRotationCookie})
	rec := httptest.NewRecorder()
	w.csrfMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"pre-rotation form token must not validate against post-rotation cookie")
}
