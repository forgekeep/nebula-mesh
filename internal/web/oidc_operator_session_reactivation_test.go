package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestOIDCOperatorSession_SEC_PERSIST_001_CannotReviveAfterReenable(t *testing.T) {
	newOperator := func(t *testing.T, ctx context.Context, s store.Store, idp *mockIDP) *models.Operator {
		t.Helper()
		op := &models.Operator{
			ID: "oidc-admin", Username: "oidc-admin", DisplayName: "OIDC Admin",
			PasswordHash: "oidc", AuthProvider: models.OperatorAuthOIDC,
			Status: models.OperatorStatusActive, Role: models.OperatorRoleAdmin,
			OIDCIssuer: idp.Issuer(), OIDCSubject: "disabled-admin-subject",
		}
		if err := s.CreateOperator(ctx, op); err != nil {
			t.Fatal(err)
		}
		if err := s.DisableOperator(ctx, op.ID); err != nil {
			t.Fatal(err)
		}
		return op
	}

	t.Run("disabled callback cannot create a session", func(t *testing.T) {
		ctx := context.Background()
		w, s := newTestWeb(t)
		idp := setupOIDCServer(t)
		o := newOIDCFromMock(t, idp, s, config.OIDCConfig{DefaultRole: "user"})
		w.WithOIDC(o)
		op := newOperator(t, ctx, s, idp)
		idp.NextIDToken(map[string]any{
			"sub": op.OIDCSubject, "aud": "test-client",
			"preferred_username": op.Username, "name": op.DisplayName,
		})

		response := driveCallback(t, o, "disabled-operator-state", "probe-code")
		if response.Code != http.StatusForbidden {
			t.Fatalf("callback for disabled operator = %d, want 403; body = %s", response.Code, response.Body.String())
		}
		for _, cookie := range response.Result().Cookies() {
			if cookie.Name == sessionCookieName && cookie.Value != "" {
				t.Fatal("callback for disabled operator created an authenticated session cookie")
			}
		}
	})

	t.Run("enable deletes a dormant session", func(t *testing.T) {
		ctx := context.Background()
		w, s := newTestWeb(t)
		idp := setupOIDCServer(t)
		op := newOperator(t, ctx, s, idp)

		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		if err := w.session.StartAuthenticatedSession(recorder, request, op); err != nil {
			t.Fatal(err)
		}
		var dormantCookie *http.Cookie
		for _, cookie := range recorder.Result().Cookies() {
			if cookie.Name == sessionCookieName {
				dormantCookie = cookie
			}
		}
		if dormantCookie == nil {
			t.Fatal("failed to seed dormant session")
		}

		if err := s.EnableOperator(ctx, op.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetOperatorBySession(ctx, dormantCookie.Value); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("dormant session lookup after enable = %v, want ErrNotFound", err)
		}

		operatorRequest := httptest.NewRequest(http.MethodGet, "/ui/operators", nil)
		operatorRequest.AddCookie(dormantCookie)
		operatorResponse := httptest.NewRecorder()
		w.ServeHTTP(operatorResponse, operatorRequest)
		if operatorResponse.Code != http.StatusSeeOther {
			t.Fatalf("retained cookie after re-enable = %d, want 303", operatorResponse.Code)
		}
	})
}
