package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

const (
	testPassword = "test-password-123"
	testUsername = "admin"
)

func newTestWeb(t *testing.T) (*Web, *store.SQLiteStore) {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	// Seed an admin operator that tests can log in as.
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperator(context.Background(), &models.Operator{
		ID:           "admin-test-id",
		Username:     testUsername,
		DisplayName:  "Administrator",
		PasswordHash: string(hash),
		Role:         "admin",
	}); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w, err := New(s, logger)
	if err != nil {
		t.Fatal(err)
	}
	return w, s
}

func loginSession(t *testing.T, w *Web) []*http.Cookie {
	t.Helper()

	// Step 1: GET /ui/login to obtain CSRF cookie
	getReq := httptest.NewRequest(http.MethodGet, "/ui/login", nil)
	getRec := httptest.NewRecorder()
	w.ServeHTTP(getRec, getReq)

	var csrfCookie *http.Cookie
	for _, c := range getRec.Result().Cookies() {
		if c.Name == csrfCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected CSRF cookie from GET /ui/login")
	}

	// Step 2: POST /ui/login with credentials and CSRF token
	form := url.Values{
		"username": {testUsername},
		"password": {testPassword},
		"_csrf":    {csrfCookie.Value},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(csrfCookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec.Result().Cookies()
}

// getCSRFTokenFromCookies extracts CSRF token from a GET request and returns updated cookies with CSRF cookie.
func getCSRFTokenFromCookies(t *testing.T, w *Web, path string, cookies []*http.Cookie) (string, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	// Extract CSRF token from form
	body := rec.Body.String()
	start := strings.Index(body, `<input type="hidden" name="_csrf" value="`)
	if start < 0 {
		t.Fatal("CSRF token not found in form")
	}
	start += len(`<input type="hidden" name="_csrf" value="`)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		t.Fatal("CSRF token closing quote not found")
	}
	token := body[start : start+end]

	// Get CSRF cookie from response
	var csrfCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrfCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie != nil {
		// Add CSRF cookie to cookies list
		cookies = append(cookies, csrfCookie)
	}

	return token, cookies
}

func TestLoginPage(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest(http.MethodGet, "/ui/login", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Sign In") {
		t.Error("login page should contain Sign In button")
	}
}

func TestLogin_Success(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	if len(cookies) == 0 {
		t.Fatal("no session cookie set after login")
	}

	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Error("session cookie not found")
	}
}

// TestSession_CookieSecureFlag covers GHSA-rqfj-vv8r-xhqc: when the
// resolved cookie_secure flag is true, both the live session cookie and
// the logout-delete cookie must carry Secure. Mirrors the OIDC test for
// the state cookie.
func TestSession_CookieSecureFlag(t *testing.T) {
	w, _ := newTestWeb(t)
	w.WithCookieSecure(true)

	cookies := loginSession(t, w)
	var live *http.Cookie
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			live = c
			break
		}
	}
	if live == nil {
		t.Fatal("session cookie not set after login")
		return
	}
	if !live.Secure {
		t.Error("session cookie missing Secure attribute")
	}
	if !live.HttpOnly {
		t.Error("session cookie missing HttpOnly attribute")
	}
	if live.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie SameSite = %v, want Lax", live.SameSite)
	}

	// Re-issuing the logout cookie with mismatched attributes leaves
	// browsers holding the original — assert the delete cookie matches
	// the live cookie's fingerprint.
	csrfToken, logoutCookies := getCSRFTokenFromCookies(t, w, "/ui/login", []*http.Cookie{live})
	logoutForm := url.Values{"_csrf": {csrfToken}}
	logoutReq := httptest.NewRequest(http.MethodPost, "/ui/logout", strings.NewReader(logoutForm.Encode()))
	logoutReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range logoutCookies {
		logoutReq.AddCookie(c)
	}
	logoutRec := httptest.NewRecorder()
	w.ServeHTTP(logoutRec, logoutReq)
	var del *http.Cookie
	for _, c := range logoutRec.Result().Cookies() {
		if c.Name == sessionCookieName {
			del = c
		}
	}
	if del == nil {
		t.Fatal("logout did not emit a session-cookie delete")
		return
	}
	if !del.Secure || !del.HttpOnly || del.SameSite != http.SameSiteLaxMode {
		t.Errorf("logout cookie attribute drift: Secure=%v HttpOnly=%v SameSite=%v",
			del.Secure, del.HttpOnly, del.SameSite)
	}
}

// TestSession_CookieSecureDefault confirms that without an explicit
// WithCookieSecure call, the cookie is NOT marked Secure — required so
// plain-HTTP local development stays usable.
func TestSession_CookieSecureDefault(t *testing.T) {
	w, _ := newTestWeb(t)
	for _, c := range loginSession(t, w) {
		if c.Name == sessionCookieName && c.Secure {
			t.Error("session cookie unexpectedly Secure when flag not set")
		}
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	w, _ := newTestWeb(t)
	csrfToken, csrfCookies := getCSRFTokenFromCookies(t, w, "/ui/login", nil)
	form := url.Values{"username": {testUsername}, "password": {"wrong"}, "_csrf": {csrfToken}}
	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range csrfCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Error("should show error message")
	}
}

func TestLogin_DisabledOperator(t *testing.T) {
	w, s := newTestWeb(t)
	ctx := context.Background()
	if err := s.DisableOperator(ctx, "admin-test-id"); err != nil {
		t.Fatal(err)
	}
	csrfToken, csrfCookies := getCSRFTokenFromCookies(t, w, "/ui/login", nil)
	form := url.Values{"username": {testUsername}, "password": {testPassword}, "_csrf": {csrfToken}}
	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range csrfCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Error("disabled operator should not be able to log in")
	}
}

func TestProtectedRouteRedirect(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 redirect", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/ui/login" {
		t.Errorf("redirect to %q, want /ui/login", loc)
	}
}

func TestDashboard_Authenticated(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "demo", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHost(ctx, &models.Host{
		ID: "h1", NetworkID: "net1", Name: "web-1", NebulaIPs: []string{"10.0.0.1"},
		Groups: []string{"web"}, Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Error("dashboard should contain 'Dashboard' title")
	}
	if !strings.Contains(body, `title="net1"`) {
		t.Error("Recent Hosts cell should contain network UUID as tooltip")
	}
	if !strings.Contains(body, ">demo<") {
		t.Error("Recent Hosts cell should render network name 'demo'")
	}
}

func TestHostsPage(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	// Create test data
	ctx := context.Background()
	s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "test", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now()})
	s.CreateHost(ctx, &models.Host{
		ID: "h1", NetworkID: "net1", Name: "web-1", NebulaIPs: []string{"10.0.0.1"},
		Groups: []string{"web"}, Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "web-1") {
		t.Error("hosts page should contain host name 'web-1'")
	}
	if !strings.Contains(body, "<th>Network</th>") {
		t.Error("hosts page should contain Network column header")
	}
	if !strings.Contains(body, `title="net1"`) {
		t.Error("hosts page should contain network UUID as tooltip")
	}
	if !strings.Contains(body, ">test<") {
		t.Error("hosts page should render network name 'test'")
	}
}

func TestNetworksPage(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "prod", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now()})

	req := httptest.NewRequest(http.MethodGet, "/ui/networks", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "prod") {
		t.Error("networks page should contain network name 'prod'")
	}
}

func TestCreateHostViaUI(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "test", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now()})

	// Get CSRF token
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)

	form := url.Values{
		"network_id": {"net1"},
		"name":       {"new-host"},
		"nebula_ips": {"10.0.0.5"},
		"role":       {"host"},
		"_csrf":      {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "new-host") {
		t.Error("response should contain host name")
	}
	// Should display enrollment token
	if !strings.Contains(body, "token-display") {
		t.Error("response should contain enrollment token display")
	}
}

func TestCreateHostViaUI_InvalidPort(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "test", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now()})

	// Get CSRF token
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)

	form := url.Values{
		"network_id":  {"net1"},
		"name":        {"bad-port-host"},
		"nebula_ips":  {"10.0.0.5"},
		"listen_port": {"70000"},
		"_csrf":       {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for port 70000, got %d", rec.Code)
	}
}

func TestLogout(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	// Extract CSRF cookie from login response
	var csrfToken string
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			csrfToken = c.Value
			break
		}
	}
	if csrfToken == "" {
		t.Fatal("expected CSRF cookie after login")
	}

	// POST /ui/logout with CSRF token
	form := url.Values{"_csrf": {csrfToken}}
	req := httptest.NewRequest(http.MethodPost, "/ui/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("logout: status = %d, want 303", rec.Code)
	}

	// After logout, dashboard should redirect to login
	req = httptest.NewRequest(http.MethodGet, "/ui/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("after logout: status = %d, want 303 redirect", rec.Code)
	}
}

func TestIsAuthenticated_ExpiredSession(t *testing.T) {
	_, s := newTestWeb(t)
	sm := NewSessionManager(s)

	token := "expired-token-123"
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token: token, OperatorID: "admin-test-id", ExpiresAt: time.Now().Add(-1 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	if sm.IsAuthenticated(req) {
		t.Error("expired session should not be authenticated")
	}
}

func TestIsAuthenticated_ValidSession(t *testing.T) {
	_, s := newTestWeb(t)
	sm := NewSessionManager(s)

	token := "valid-token-456"
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token: token, OperatorID: "admin-test-id", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	if !sm.IsAuthenticated(req) {
		t.Error("valid session should be authenticated")
	}
}

func TestIsAuthenticated_NoCookie(t *testing.T) {
	_, s := newTestWeb(t)
	sm := NewSessionManager(s)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if sm.IsAuthenticated(req) {
		t.Error("request without cookie should not be authenticated")
	}
}

func TestIsAuthenticated_DisabledOperator(t *testing.T) {
	_, s := newTestWeb(t)
	sm := NewSessionManager(s)

	token := "tok-disabled"
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token: token, OperatorID: "admin-test-id", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DisableOperator(context.Background(), "admin-test-id"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	if sm.IsAuthenticated(req) {
		t.Error("disabled operator's session should not be authenticated")
	}
}

func TestSessionCleanup(t *testing.T) {
	_, s := newTestWeb(t)
	sm := NewSessionManager(s)
	ctx := context.Background()

	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token: "expired-1", OperatorID: "admin-test-id", ExpiresAt: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token: "valid-1", OperatorID: "admin-test-id", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	cleanupCtx, cancel := context.WithCancel(context.Background())
	sm.StartCleanup(cleanupCtx, 50*time.Millisecond)
	time.Sleep(150 * time.Millisecond)
	cancel()

	if _, err := s.GetOperatorBySession(ctx, "valid-1"); err != nil {
		t.Errorf("valid session removed: %v", err)
	}
	if _, err := s.GetOperatorBySession(ctx, "expired-1"); err == nil {
		t.Error("expired session should have been cleaned up")
	}
}

func TestBuildHostViews(t *testing.T) {
	netA := &models.Network{ID: "net-a", Name: "alpha"}
	netB := &models.Network{ID: "net-b", Name: "beta"}
	h1 := &models.Host{ID: "h1", NetworkID: "net-a", Name: "web-1"}
	h2 := &models.Host{ID: "h2", NetworkID: "net-b", Name: "web-2"}
	hOrphan := &models.Host{ID: "h3", NetworkID: "missing", Name: "orphan"}

	tests := []struct {
		name     string
		hosts    []*models.Host
		networks []*models.Network
		want     []struct {
			hostID, networkName string
		}
	}{
		{
			name:     "empty hosts and networks",
			hosts:    nil,
			networks: nil,
			want:     nil,
		},
		{
			name:     "empty hosts, networks present",
			hosts:    nil,
			networks: []*models.Network{netA},
			want:     nil,
		},
		{
			name:     "hosts with known networks",
			hosts:    []*models.Host{h1, h2},
			networks: []*models.Network{netA, netB},
			want: []struct{ hostID, networkName string }{
				{"h1", "alpha"},
				{"h2", "beta"},
			},
		},
		{
			name:     "host with unknown network falls back to empty NetworkName",
			hosts:    []*models.Host{h1, hOrphan},
			networks: []*models.Network{netA},
			want: []struct{ hostID, networkName string }{
				{"h1", "alpha"},
				{"h3", ""},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildHostViews(tc.hosts, tc.networks)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tc.want))
			}
			for i, w := range tc.want {
				if got[i].Host == nil {
					t.Fatalf("got[%d].Host is nil", i)
				}
				if got[i].ID != w.hostID {
					t.Errorf("got[%d].ID = %q, want %q", i, got[i].ID, w.hostID)
				}
				if got[i].NetworkName != w.networkName {
					t.Errorf("got[%d].NetworkName = %q, want %q", i, got[i].NetworkName, w.networkName)
				}
			}
		})
	}
}

func TestFavicon(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Errorf("Content-Type = %q, want image/svg+xml", ct)
	}
	if rec.Body.Len() == 0 {
		t.Error("favicon body should not be empty")
	}
}

func TestStaticFiles(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("htmx.min.js should not be empty")
	}
}

func TestParseTemplates_IncludesHostEdit(t *testing.T) {
	w, _ := newTestWeb(t)
	// If template parsing fails, newTestWeb will have panicked in New().
	// Verify host_edit.html template was successfully registered.
	if w.templates["host_edit.html"] == nil {
		t.Error("host_edit.html template not registered")
	}
}

func TestRenderInjectsCSRFToken(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	// GET /ui/hosts (authenticated, uses layout.html)
	req := httptest.NewRequest(http.MethodGet, "/ui/hosts", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	// Assert <meta name="csrf-token" content="..."> is present
	if !strings.Contains(body, `<meta name="csrf-token" content="`) {
		t.Error("response does not contain <meta name=\"csrf-token\">")
	}
	// Extract and validate non-empty token value
	start := strings.Index(body, `<meta name="csrf-token" content="`)
	if start >= 0 {
		start += len(`<meta name="csrf-token" content="`)
		end := strings.Index(body[start:], `"`)
		if end > 0 {
			token := body[start : start+end]
			if token == "" {
				t.Error("csrf-token meta tag has empty content")
			}
		}
	}
}

func TestRenderInjectsCSRFTokenPreAuth(t *testing.T) {
	w, _ := newTestWeb(t)

	// GET /ui/login (pre-auth, does not use layout.html, but csrf token should still be in response)
	req := httptest.NewRequest(http.MethodGet, "/ui/login", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()
	// Assert csrf token is present in form as hidden input
	if !strings.Contains(body, `<input type="hidden" name="_csrf"`) {
		t.Error("response does not contain csrf hidden input")
	}
	// Verify the token value is non-empty
	startIdx := strings.Index(body, `<input type="hidden" name="_csrf" value="`)
	if startIdx >= 0 {
		startIdx += len(`<input type="hidden" name="_csrf" value="`)
		endIdx := strings.Index(body[startIdx:], `"`)
		if endIdx > 0 {
			token := body[startIdx : startIdx+endIdx]
			if token == "" {
				t.Error("csrf token value is empty")
			}
		}
	}
}
