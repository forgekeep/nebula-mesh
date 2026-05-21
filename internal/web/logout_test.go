package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLogoutRoute_GETReturns405 verifies that GET /ui/logout is rejected
// with 405 Method Not Allowed (or similar error status).
func TestLogoutRoute_GETReturns405(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	req := httptest.NewRequest(http.MethodGet, "/ui/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	// Chi returns 405 Method Not Allowed for unregistered methods
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code,
		"GET /ui/logout should be rejected; expected 405 Method Not Allowed")
}

// TestLogoutRoute_POSTWithCSRFSucceeds verifies that POST /ui/logout
// with correct CSRF cookie+token returns 303 redirect to /ui/login.
func TestLogoutRoute_POSTWithCSRFSucceeds(t *testing.T) {
	w, _ := newTestWeb(t)

	// Step 1: GET /ui/login to get CSRF cookie
	getReq := httptest.NewRequest(http.MethodGet, "/ui/login", nil)
	getRec := httptest.NewRecorder()
	w.ServeHTTP(getRec, getReq)
	getCSRFCookie := getCSRFCookieFromResponse(getRec)
	require.NotNil(t, getCSRFCookie, "expected CSRF cookie from GET /ui/login")

	// Step 2: POST /ui/login with credentials and CSRF token
	loginForm := url.Values{
		"username": {testUsername},
		"password": {testPassword},
		"_csrf":    {getCSRFCookie.Value},
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/ui/login",
		strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.AddCookie(getCSRFCookie)

	loginRec := httptest.NewRecorder()
	w.ServeHTTP(loginRec, loginReq)
	require.Equal(t, http.StatusSeeOther, loginRec.Code, "login should succeed")

	// Step 3: Extract session and CSRF cookies from login response
	var sessionCookie, csrfCookie *http.Cookie
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
		}
		if c.Name == csrfCookieName {
			csrfCookie = c
		}
	}
	require.NotNil(t, sessionCookie, "expected session cookie from login")
	require.NotNil(t, csrfCookie, "expected CSRF cookie from login response")

	// Step 4: POST /ui/logout with CSRF token in form
	logoutForm := url.Values{
		"_csrf": {csrfCookie.Value},
	}
	logoutReq := httptest.NewRequest(http.MethodPost, "/ui/logout",
		strings.NewReader(logoutForm.Encode()))
	logoutReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logoutReq.AddCookie(sessionCookie)
	logoutReq.AddCookie(csrfCookie)

	logoutRec := httptest.NewRecorder()
	w.ServeHTTP(logoutRec, logoutReq)

	require.Equal(t, http.StatusSeeOther, logoutRec.Code,
		"POST /ui/logout with CSRF should succeed; expected 303 redirect")
	location := logoutRec.Header().Get("Location")
	assert.Equal(t, "/ui/login", location,
		"logout should redirect to /ui/login")
}

// getCSRFCookieFromResponse extracts the CSRF cookie from an HTTP response.
func getCSRFCookieFromResponse(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			return c
		}
	}
	return nil
}
