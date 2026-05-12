package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRegister_DisabledByDefault(t *testing.T) {
	w, _ := newTestWeb(t)

	req := httptest.NewRequest("GET", "/ui/register", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("GET /ui/register = %d, want 403", rec.Code)
	}

	form := url.Values{"username": {"alice"}, "password": {"correcthorse"}, "password_confirm": {"correcthorse"}}
	req = httptest.NewRequest("POST", "/ui/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST /ui/register = %d, want 403", rec.Code)
	}
}

func TestRegister_Enabled_CreatesOperator(t *testing.T) {
	w, s := newTestWeb(t)
	w.AllowSelfRegistration(true)

	form := url.Values{
		"username":         {"alice"},
		"display_name":     {"Alice"},
		"password":         {"correcthorse"},
		"password_confirm": {"correcthorse"},
	}
	req := httptest.NewRequest("POST", "/ui/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	op, err := s.GetOperatorByUsername(context.Background(), "alice")
	if err != nil {
		t.Fatalf("operator not created: %v", err)
	}
	if op.Role != "user" {
		t.Errorf("role = %q, want user", op.Role)
	}
}

func TestRegister_RejectsDuplicateUsername(t *testing.T) {
	w, _ := newTestWeb(t)
	w.AllowSelfRegistration(true)

	form := url.Values{
		"username":         {testUsername}, // admin from newTestWeb seed
		"password":         {"correcthorse"},
		"password_confirm": {"correcthorse"},
	}
	req := httptest.NewRequest("POST", "/ui/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Username already taken") {
		t.Errorf("expected duplicate-username error; body=%s", rec.Body.String())
	}
}

func TestRegister_RejectsShortPassword(t *testing.T) {
	w, _ := newTestWeb(t)
	w.AllowSelfRegistration(true)

	form := url.Values{"username": {"bob"}, "password": {"short"}, "password_confirm": {"short"}}
	req := httptest.NewRequest("POST", "/ui/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "at least 8") {
		t.Errorf("expected short-password error; body=%s", rec.Body.String())
	}
}

func TestRegister_RejectsMismatchedConfirmation(t *testing.T) {
	w, _ := newTestWeb(t)
	w.AllowSelfRegistration(true)

	form := url.Values{"username": {"carol"}, "password": {"correcthorse"}, "password_confirm": {"different1"}}
	req := httptest.NewRequest("POST", "/ui/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "confirmation does not match") {
		t.Errorf("expected confirmation-mismatch error; body=%s", rec.Body.String())
	}
}

func TestLoginPage_ShowsRegisterLinkOnlyWhenEnabled(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest("GET", "/ui/login", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "Create an account") {
		t.Error("register link should be hidden when self-registration is disabled")
	}

	w.AllowSelfRegistration(true)
	req = httptest.NewRequest("GET", "/ui/login", nil)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Create an account") {
		t.Error("register link should appear when self-registration is enabled")
	}
}
