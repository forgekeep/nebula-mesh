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

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func newEnforceWeb(t *testing.T) (*Web, store.Store) {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	w, err := New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return w, s
}

// seedLocalOperator creates an active local operator with the given
// password. TOTP is left disabled so the enforce-2fa flow gates the
// session.
func seedLocalOperator(t *testing.T, s store.Store, username, password string, oidc bool) *models.Operator {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	provider := models.OperatorAuthLocal
	if oidc {
		provider = models.OperatorAuthOIDC
	}
	op := &models.Operator{
		ID:           "op-" + username,
		Username:     username,
		PasswordHash: string(hash),
		Status:       models.OperatorStatusActive,
		Role:         "admin",
		AuthProvider: provider,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	return op
}

func loginOperator(t *testing.T, w *Web, username, password string) *http.Cookie {
	t.Helper()
	// Get CSRF token from login page
	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/login", nil)

	form := url.Values{
		"username": {username},
		"password": {password},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "nebula_session" {
			return c
		}
	}
	t.Fatalf("login: no session cookie issued; status=%d body=%s", rec.Code, rec.Body.String())
	return nil
}

func TestEnforce2FA_Off_NoGating(t *testing.T) {
	w, s := newEnforceWeb(t)
	seedLocalOperator(t, s, "alice", strongPassword, false)

	cookie := loginOperator(t, w, "alice", strongPassword)
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code == http.StatusSeeOther && rec.Header().Get("Location") == "/ui/2fa/required" {
		t.Errorf("with enforce_2fa off, dashboard must not redirect to /ui/2fa/required")
	}
}

func TestEnforce2FA_On_LocalUser_Gated(t *testing.T) {
	w, s := newEnforceWeb(t)
	seedLocalOperator(t, s, "alice", strongPassword, false)
	if err := s.SetServerSetting(context.Background(), SettingEnforceTOTP, "true"); err != nil {
		t.Fatal(err)
	}

	cookie := loginOperator(t, w, "alice", strongPassword)
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("dashboard fetch: status = %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/ui/2fa/required" {
		t.Errorf("redirect = %q, want /ui/2fa/required", loc)
	}
}

func TestEnforce2FA_On_OIDC_NotGated(t *testing.T) {
	// OIDC operators do their 2FA at the IdP and must bypass the gate.
	w, s := newEnforceWeb(t)
	op := seedLocalOperator(t, s, "alice", strongPassword, true)
	if err := s.SetServerSetting(context.Background(), SettingEnforceTOTP, "true"); err != nil {
		t.Fatal(err)
	}

	// Manually mint an authenticated session — OIDC users normally
	// arrive via the OIDC callback path, not POST /ui/login.
	tok := "oidc-test-token"
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      tok,
		OperatorID: op.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.AddCookie(&http.Cookie{Name: "nebula_session", Value: tok})
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code == http.StatusSeeOther && rec.Header().Get("Location") == "/ui/2fa/required" {
		t.Errorf("OIDC user must not be gated; got redirect to /ui/2fa/required")
	}
}

func TestEnforce2FA_On_DisableBlocked(t *testing.T) {
	w, s := newEnforceWeb(t)
	op := seedLocalOperator(t, s, "alice", strongPassword, false)
	// Pretend TOTP is already enabled so the operator can hit the
	// disable handler in the first place.
	if err := s.SetOperatorTOTP(context.Background(), op.ID, "JBSWY3DPEHPK3PXP", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetServerSetting(context.Background(), SettingEnforceTOTP, "true"); err != nil {
		t.Fatal(err)
	}

	cookie := loginOperator(t, w, "alice", strongPassword)
	// loginOperator above issues a pending_totp session — promote it by
	// driving CompleteTwoFactor directly so we land on /ui/2fa/disable
	// authenticated.
	if err := s.PromoteOperatorSession(context.Background(), cookie.Value, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Get CSRF token from /ui/2fa page (which displays the disable form on the page).
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/2fa", []*http.Cookie{cookie})

	form := url.Values{
		"password": {strongPassword},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/2fa/disable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("disable: status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "admin-enforced") {
		t.Errorf("expected admin-enforced explanation in body, got %s", rec.Body.String())
	}

	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "operator.2fa.enforced.disable_blocked", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("audit entries: got %d, want 1", len(entries))
	}
}

func TestEnforce2FA_On_RequiredPath_Reachable(t *testing.T) {
	w, s := newEnforceWeb(t)
	seedLocalOperator(t, s, "alice", strongPassword, false)
	if err := s.SetServerSetting(context.Background(), SettingEnforceTOTP, "true"); err != nil {
		t.Fatal(err)
	}

	cookie := loginOperator(t, w, "alice", strongPassword)
	req := httptest.NewRequest(http.MethodGet, "/ui/2fa/required", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui/2fa/required: status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "2") { // some 2FA-related content
		t.Errorf("page body looks empty: %s", rec.Body.String())
	}
}
