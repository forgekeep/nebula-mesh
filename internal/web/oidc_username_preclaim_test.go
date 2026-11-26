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

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func newEmptyPreclaimWeb(t *testing.T) (*Web, *store.SQLiteStore) {
	t.Helper()
	s, err := openTestSQLiteStore(t)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	w, err := New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return w, s
}

func TestOIDCUsernamePreclaim_SEC_PERSIST_001_DoesNotBlockOrLinkFirstAdmin(t *testing.T) {
	newClaims := func() map[string]any {
		return map[string]any{
			"sub": "sole-admin-subject", "aud": "test-client",
			"preferred_username": "sole-admin", "groups": []any{"nebula-admins"},
		}
	}
	newIDP := func(t *testing.T, s store.Store, w *Web) (*OIDC, *mockIDP) {
		t.Helper()
		idp := setupOIDCServer(t)
		o := newOIDCFromMock(t, idp, s, config.OIDCConfig{
			AllowedGroups: []string{"nebula-admins"}, DefaultRole: "admin",
		})
		w.WithOIDC(o)
		return o, idp
	}

	t.Run("anonymous registration cannot preclaim OIDC identity", func(t *testing.T) {
		w, s := newEmptyPreclaimWeb(t)
		w.AllowSelfRegistration(true)
		o, idp := newIDP(t, s, w)

		csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/register", nil)
		form := url.Values{
			"username": {"sole-admin"}, "password": {strongPassword},
			"password_confirm": {strongPassword}, "_csrf": {csrfToken},
		}
		registration := httptest.NewRequest(http.MethodPost, "/ui/register", strings.NewReader(form.Encode()))
		registration.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, cookie := range cookies {
			registration.AddCookie(cookie)
		}
		registrationResponse := httptest.NewRecorder()
		w.ServeHTTP(registrationResponse, registration)
		if registrationResponse.Code != http.StatusSeeOther {
			t.Fatalf("registration = %d, want 303; body = %s", registrationResponse.Code, registrationResponse.Body.String())
		}

		idp.NextIDToken(newClaims())
		loginResponse := driveCallback(t, o, "preclaimed-state", "probe-code")
		if loginResponse.Code != http.StatusSeeOther {
			t.Fatalf("OIDC callback after preclaim = %d, want 303; body = %s", loginResponse.Code, loginResponse.Body.String())
		}
		admin, err := s.GetOperatorByOIDC(context.Background(), idp.Issuer(), "sole-admin-subject")
		if err != nil {
			t.Fatal(err)
		}
		if admin.Role != models.OperatorRoleAdmin || admin.Username == "sole-admin" {
			t.Fatalf("provisioned OIDC operator = %#v, want admin with collision-safe username", admin)
		}
		preclaimed, err := s.GetOperatorByUsername(context.Background(), "sole-admin")
		if err != nil {
			t.Fatal(err)
		}
		if preclaimed.ID == admin.ID || preclaimed.Role != models.OperatorRoleUser || preclaimed.AuthProvider != models.OperatorAuthLocal || preclaimed.OIDCSubject != "" {
			t.Fatalf("preclaimed local account was linked or elevated: %#v", preclaimed)
		}

		settings := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
		for _, cookie := range loginResponse.Result().Cookies() {
			settings.AddCookie(cookie)
		}
		settingsResponse := httptest.NewRecorder()
		w.ServeHTTP(settingsResponse, settings)
		if settingsResponse.Code != http.StatusOK {
			t.Fatalf("OIDC admin settings = %d, want 200", settingsResponse.Code)
		}
	})

	t.Run("uncontested first login preserves preferred username", func(t *testing.T) {
		w, s := newEmptyPreclaimWeb(t)
		w.AllowSelfRegistration(true)
		o, idp := newIDP(t, s, w)
		idp.NextIDToken(newClaims())
		loginResponse := driveCallback(t, o, "control-state", "probe-code")
		if loginResponse.Code != http.StatusSeeOther {
			t.Fatalf("clean OIDC callback = %d, want 303; body = %s", loginResponse.Code, loginResponse.Body.String())
		}
		admin, err := s.GetOperatorByOIDC(context.Background(), idp.Issuer(), "sole-admin-subject")
		if err != nil {
			t.Fatal(err)
		}
		if admin.Username != "sole-admin" || admin.Role != models.OperatorRoleAdmin {
			t.Fatalf("clean first-login operator = %#v", admin)
		}
	})
}
