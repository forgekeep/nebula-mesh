package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestDisableOperator_KillsActiveOIDCSession pins the disable-cascade
// contract for OIDC-authenticated sessions. Local-auth sessions are
// already covered in store/sqlite_operators_test.go; this variant
// guards against a future refactor that partitions sessions by
// auth_provider against the OIDC path specifically.
func TestDisableOperator_KillsActiveOIDCSession(t *testing.T) {
	ctx := context.Background()
	s, err := openTestSQLiteStore(t)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	op := &models.Operator{
		ID:           "oidc-user-id",
		Username:     "oidc-user@example.com",
		DisplayName:  "OIDC User",
		PasswordHash: "oidc", // matches oidc.go::upsertOperator's placeholder
		Role:         "admin",
		AuthProvider: models.OperatorAuthOIDC,
		OIDCIssuer:   "https://idp.example.com",
		OIDCSubject:  "sub-12345",
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatalf("create OIDC operator: %v", err)
	}

	sm := NewSessionManager(s)

	// Mint a session via the same SessionManager method the OIDC
	// callback uses (oidc.go HandleCallback -> session.StartAuthenticatedSession).
	rec := httptest.NewRecorder()
	startReq := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := sm.StartAuthenticatedSession(rec, startReq, op); err != nil {
		t.Fatalf("StartAuthenticatedSession: %v", err)
	}

	// Lift the session cookie back into a request, the way a browser
	// would carry it across calls.
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("StartAuthenticatedSession did not set a session cookie")
	}

	carryCookie := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(sessionCookie)
		return r
	}

	// Pre-disable: the session authenticates the OIDC operator.
	if !sm.IsAuthenticated(carryCookie()) {
		t.Fatal("OIDC session should authenticate before disable")
	}
	if got := sm.CurrentOperator(carryCookie()); got == nil || got.ID != op.ID {
		t.Fatalf("CurrentOperator pre-disable = %v, want operator %q", got, op.ID)
	}

	// Disable the OIDC operator. DisableOperator's atomic transaction
	// must delete the session row alongside the status flip — same
	// cascade local-auth operators get.
	if err := s.DisableOperator(ctx, op.ID); err != nil {
		t.Fatalf("DisableOperator: %v", err)
	}

	// Post-disable: the session must no longer authenticate.
	if sm.IsAuthenticated(carryCookie()) {
		t.Error("OIDC session still authenticates after DisableOperator (cascade broken)")
	}
	if got := sm.CurrentOperator(carryCookie()); got != nil {
		t.Errorf("CurrentOperator post-disable = %v, want nil", got)
	}

	// Verify the row is gone, not just filtered.
	if _, err := s.GetOperatorBySession(ctx, sessionCookie.Value); err == nil {
		t.Error("expected ErrNotFound from GetOperatorBySession; row still present")
	}
}
