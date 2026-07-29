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

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func newSettingsWeb(t *testing.T) (*Web, store.Store) {
	t.Helper()
	s, err := openTestSQLiteStore(t)
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

// authedSession mints an authenticated session for the given role and
// returns a cookie callers can attach to subsequent requests.
func authedSession(t *testing.T, s store.Store, username, role string) *http.Cookie {
	t.Helper()
	op := &models.Operator{
		ID:           "op-" + username,
		Username:     username,
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         role,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	tok := "session-" + username
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      tok,
		OperatorID: op.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: "nebula_session", Value: tok}
}

func TestSettings_NonAdmin_403(t *testing.T) {
	w, s := newSettingsWeb(t)
	cookie := authedSession(t, s, "alice", "user")

	req := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestSettings_Admin_FlipsAndPersists(t *testing.T) {
	w, s := newSettingsWeb(t)
	cookie := authedSession(t, s, "root", "admin")

	// Get CSRF token for settings form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/settings", []*http.Cookie{cookie})

	form := url.Values{
		"enforce_2fa":              {"1"},
		"allow_self_registration":  {"1"},
		"password_block_common":    {"1"},
		"password_block_username":  {"1"},
		"password_min_length":      {"16"},
		"password_require_classes": {"4"},
		"log_level":                {"warn"},
		"_csrf":                    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Settings saved") {
		t.Errorf("expected 'Settings saved' banner; body=%s", rec.Body.String())
	}

	// DB-backed reads should now return the new values.
	ctx := context.Background()
	if !enforceTOTPEnabled(ctx, s) {
		t.Error("enforce_2fa was not persisted")
	}
	if v, _ := s.GetServerSetting(ctx, SettingPasswordMinLength); v != "16" {
		t.Errorf("password_min_length = %q, want 16", v)
	}
	if v, _ := s.GetServerSetting(ctx, SettingLogLevel); v != "warn" {
		t.Errorf("log_level = %q, want warn", v)
	}

	// Audit entry recorded.
	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Action: "settings.update", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("audit entries: got %d, want 1", len(entries))
	}
}

func TestSettings_Unchecked_CheckboxSetsFalse(t *testing.T) {
	w, s := newSettingsWeb(t)
	// Seed allow_self_registration=true; an empty POST must flip it back
	// to false because HTML checkboxes only send a value when ticked.
	if err := s.SetServerSetting(context.Background(), SettingAllowSelfRegistration, "true"); err != nil {
		t.Fatal(err)
	}
	cookie := authedSession(t, s, "root", "admin")

	// Get CSRF token for settings form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/settings", []*http.Cookie{cookie})

	form := url.Values{
		"_csrf": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	if boolSetting(context.Background(), s, SettingAllowSelfRegistration, false) {
		t.Error("unchecked checkbox should have set allow_self_registration back to false")
	}
}

func TestSettings_NonAdmin_PostForbidden(t *testing.T) {
	w, s := newSettingsWeb(t)
	cookie := authedSession(t, s, "alice", "user")

	form := url.Values{"enforce_2fa": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}

	// And the setting should not have moved.
	if enforceTOTPEnabled(context.Background(), s) {
		t.Error("non-admin POST should not change enforce_2fa")
	}
}

func TestSettings_PageUsesFormGroupPattern(t *testing.T) {
	w, s := newSettingsWeb(t)
	cookie := authedSession(t, s, "root", "admin")

	req := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify presence of form-group wrapper (at least 5 form fields).
	formGroupCount := strings.Count(body, `class="form-group"`)
	if formGroupCount < 5 {
		t.Errorf("form-group count = %d, want >= 5; body=%s", formGroupCount, body)
	}

	// Verify presence of form-control class (at least 3: 2 number inputs + 1 select).
	formControlCount := strings.Count(body, `class="form-control"`)
	if formControlCount < 3 {
		t.Errorf("form-control count = %d, want >= 3", formControlCount)
	}
}

func TestSettings_SaveShowsFlashSuccess(t *testing.T) {
	w, s := newSettingsWeb(t)
	cookie := authedSession(t, s, "root", "admin")

	// Get CSRF token for settings form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/settings", []*http.Cookie{cookie})

	form := url.Values{
		"enforce_2fa":              {"1"},
		"allow_self_registration":  {"1"},
		"password_block_common":    {"1"},
		"password_block_username":  {"1"},
		"password_min_length":      {"16"},
		"password_require_classes": {"4"},
		"log_level":                {"warn"},
		"_csrf":                    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify presence of flash-success class.
	if !strings.Contains(body, `class="flash flash-success"`) {
		t.Errorf("expected 'class=\"flash flash-success\"' in response body; body=%s", body)
	}

	// Verify success text is present.
	if !strings.Contains(body, "Settings saved") {
		t.Errorf("expected 'Settings saved' text in response body; body=%s", body)
	}
}

func TestSettings_NoOrphanMutedParagraph(t *testing.T) {
	w, s := newSettingsWeb(t)
	cookie := authedSession(t, s, "root", "admin")

	req := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify no orphan <p class="muted"> outside card wrapper.
	// For simplicity, check that if the muted paragraph exists, it should be wrapped.
	if strings.Contains(body, `<p class="muted">`) {
		t.Errorf("found orphan <p class=\"muted\"> — should be wrapped inside card or removed")
	}
}

func TestSettings_FormIncludesCSRFToken(t *testing.T) {
	w, s := newSettingsWeb(t)
	cookie := authedSession(t, s, "root", "admin")

	req := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify CSRF token is present in the settings form specifically.
	// The template uses {{ csrfField }} which expands to a hidden input with
	// a token value when CSRF middleware is active.
	settingsFormStart := strings.Index(body, `<form method="POST" action="/ui/settings"`)
	settingsFormEnd := strings.Index(body[settingsFormStart:], `</form>`)
	if settingsFormStart == -1 || settingsFormEnd == -1 {
		t.Fatal("could not find settings form in response")
	}

	settingsForm := body[settingsFormStart : settingsFormStart+settingsFormEnd+7]
	if !strings.Contains(settingsForm, `name="_csrf"`) {
		t.Errorf("expected CSRF token input in settings form; form=%s", settingsForm[:300])
	}
}
