package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestOperators_ResetPassword_InvalidatesSessions verifies that an admin
// resetting an operator's password terminates that operator's existing web
// sessions. Otherwise an attacker holding a pre-reset session cookie keeps
// access after the reset whose whole purpose is to revoke it (#204, CWE-613).
// Mirrors the session cascade already in DisableOperator.
func TestOperators_ResetPassword_InvalidatesSessions(t *testing.T) {
	w, s := newOperatorsWeb(t)
	admin := mintSession(t, s, "root", "admin")

	// Target operator with a live session — the "attacker-held" cookie.
	victim := mintSession(t, s, "bob", "user")

	// Precondition: bob's session is valid before the reset.
	if _, err := s.GetOperatorBySession(context.Background(), victim.Value); err != nil {
		t.Fatalf("precondition: bob session should be valid, got %v", err)
	}

	// Admin resets bob's password.
	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/operators/op-bob", []*http.Cookie{admin})
	form := url.Values{
		"password": {strongPassword + "X"},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/operators/op-bob/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reset password: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	// bob's pre-reset session must now be invalid.
	if _, err := s.GetOperatorBySession(context.Background(), victim.Value); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("bob session should be invalidated after reset, got err=%v", err)
	}
}
