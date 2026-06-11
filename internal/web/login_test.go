package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLogin_EmptyUsernameRejected verifies that POST /ui/login with an
// empty username is denied even when the password matches the admin
// account. The handler must not substitute a default username
// (GHSA-gvjh-8rm7-23h3 hardening).
func TestLogin_EmptyUsernameRejected(t *testing.T) {
	w, _ := newTestWeb(t)

	getReq := httptest.NewRequest(http.MethodGet, "/ui/login", nil)
	getRec := httptest.NewRecorder()
	w.ServeHTTP(getRec, getReq)
	csrfCookie := getCSRFCookieFromResponse(getRec)
	require.NotNil(t, csrfCookie, "expected CSRF cookie from GET /ui/login")

	for _, username := range []string{"", "   "} {
		form := url.Values{
			"username": {username},
			"password": {testPassword},
			"_csrf":    {csrfCookie.Value},
		}
		req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(csrfCookie)
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code,
			"login with username %q must re-render the login page, not redirect", username)
		require.Contains(t, rec.Body.String(), "Invalid username or password",
			"login with username %q must be denied", username)
		for _, c := range rec.Result().Cookies() {
			require.NotEqual(t, sessionCookieName, c.Name,
				"login with username %q must not issue a session cookie", username)
		}
	}
}
