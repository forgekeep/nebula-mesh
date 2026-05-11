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

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

const testPassword = "test-password-123"

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

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	w, err := New(s, testPassword, logger)
	if err != nil {
		t.Fatal(err)
	}
	return w, s
}

func loginSession(t *testing.T, w *Web) []*http.Cookie {
	t.Helper()
	form := url.Values{"password": {testPassword}}
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec.Result().Cookies()
}

func TestLoginPage(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest("GET", "/ui/login", nil)
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

func TestLogin_WrongPassword(t *testing.T) {
	w, _ := newTestWeb(t)
	form := url.Values{"password": {"wrong"}}
	req := httptest.NewRequest("POST", "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid password") {
		t.Error("should show error message")
	}
}

func TestProtectedRouteRedirect(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest("GET", "/ui/", nil)
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
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	req := httptest.NewRequest("GET", "/ui/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Dashboard") {
		t.Error("dashboard should contain 'Dashboard' title")
	}
}

func TestHostsPage(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	// Create test data
	ctx := context.Background()
	s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "test", CIDR: "10.0.0.0/24", CreatedAt: time.Now()})
	s.CreateHost(ctx, &models.Host{
		ID: "h1", NetworkID: "net1", Name: "web-1", NebulaIP: "10.0.0.1",
		Groups: []string{"web"}, Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})

	req := httptest.NewRequest("GET", "/ui/hosts", nil)
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
}

func TestNetworksPage(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "prod", CIDR: "10.0.0.0/24", CreatedAt: time.Now()})

	req := httptest.NewRequest("GET", "/ui/networks", nil)
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
	s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "test", CIDR: "10.0.0.0/24", CreatedAt: time.Now()})

	form := url.Values{
		"network_id": {"net1"},
		"name":       {"new-host"},
		"nebula_ip":  {"10.0.0.5"},
		"role":       {"host"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
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
	s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "test", CIDR: "10.0.0.0/24", CreatedAt: time.Now()})

	form := url.Values{
		"network_id":  {"net1"},
		"name":        {"bad-port-host"},
		"nebula_ip":   {"10.0.0.5"},
		"listen_port": {"70000"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
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

	req := httptest.NewRequest("GET", "/ui/logout", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}

	// After logout, dashboard should redirect to login
	req = httptest.NewRequest("GET", "/ui/", nil)
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
	sm := NewSessionManager(testPassword)

	// Manually inject an expired session
	token := "expired-token-123"
	sm.mu.Lock()
	sm.sessions[token] = session{expiresAt: time.Now().Add(-1 * time.Hour)}
	sm.mu.Unlock()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	if sm.IsAuthenticated(req) {
		t.Error("expired session should not be authenticated")
	}

	// Session should be deleted from map
	sm.mu.RLock()
	_, exists := sm.sessions[token]
	sm.mu.RUnlock()
	if exists {
		t.Error("expired session should be removed from sessions map")
	}
}

func TestIsAuthenticated_ValidSession(t *testing.T) {
	sm := NewSessionManager(testPassword)

	token := "valid-token-456"
	sm.mu.Lock()
	sm.sessions[token] = session{expiresAt: time.Now().Add(1 * time.Hour)}
	sm.mu.Unlock()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})

	if !sm.IsAuthenticated(req) {
		t.Error("valid session should be authenticated")
	}
}

func TestIsAuthenticated_NoCookie(t *testing.T) {
	sm := NewSessionManager(testPassword)
	req := httptest.NewRequest("GET", "/", nil)

	if sm.IsAuthenticated(req) {
		t.Error("request without cookie should not be authenticated")
	}
}

func TestSessionCleanup(t *testing.T) {
	sm := NewSessionManager(testPassword)

	// Inject expired sessions
	sm.mu.Lock()
	sm.sessions["expired-1"] = session{expiresAt: time.Now().Add(-2 * time.Hour)}
	sm.sessions["expired-2"] = session{expiresAt: time.Now().Add(-1 * time.Hour)}
	sm.sessions["valid-1"] = session{expiresAt: time.Now().Add(1 * time.Hour)}
	sm.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	sm.StartCleanup(ctx, 50*time.Millisecond) // short interval for test

	// Wait for cleanup tick
	time.Sleep(150 * time.Millisecond)
	cancel()

	sm.mu.RLock()
	count := len(sm.sessions)
	_, validExists := sm.sessions["valid-1"]
	sm.mu.RUnlock()

	if count != 1 {
		t.Errorf("sessions count = %d, want 1 (only valid)", count)
	}
	if !validExists {
		t.Error("valid session should survive cleanup")
	}
}

func TestStaticFiles(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest("GET", "/static/htmx.min.js", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Error("htmx.min.js should not be empty")
	}
}
