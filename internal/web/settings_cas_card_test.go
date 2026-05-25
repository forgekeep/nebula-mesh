package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestSettings_AdminSeesCAsCard(t *testing.T) {
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

	// Create admin operator and session
	adminOp := &models.Operator{
		ID:           "op-admin-1",
		Username:     "admin1",
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "admin",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(context.Background(), adminOp); err != nil {
		t.Fatal(err)
	}

	adminToken := "session-admin1"
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      adminToken,
		OperatorID: adminOp.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// GET /ui/settings as admin
	req := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	req.AddCookie(&http.Cookie{Name: "nebula_session", Value: adminToken})
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()

	// Assert: card contains "Certificate Authorities"
	if !strings.Contains(body, "Certificate Authorities") {
		t.Errorf("body does not contain 'Certificate Authorities': %s", body)
	}

	// Assert: card contains href="/ui/cas"
	if !strings.Contains(body, `href="/ui/cas"`) {
		t.Errorf("body does not contain 'href=\"/ui/cas\"': %s", body)
	}

	// Assert: card contains "Manage CAs"
	if !strings.Contains(body, "Manage CAs") {
		t.Errorf("body does not contain 'Manage CAs': %s", body)
	}
}

func TestSettings_UserDoesNotSeeCAsCard(t *testing.T) {
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

	// Create user operator and session
	userOp := &models.Operator{
		ID:           "op-user-1",
		Username:     "alice",
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(context.Background(), userOp); err != nil {
		t.Fatal(err)
	}

	userToken := "session-alice"
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      userToken,
		OperatorID: userOp.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// GET /ui/settings as user — should receive 403 (gated at handler level)
	req := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	req.AddCookie(&http.Cookie{Name: "nebula_session", Value: userToken})
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	// User should get 403, so CA card never rendered
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()

	// Even though user shouldn't reach this page, assert double-check that CA card is not there
	if strings.Contains(body, "Certificate Authorities") {
		t.Errorf("body should not contain 'Certificate Authorities' for user: %s", body)
	}

	if strings.Contains(body, `href="/ui/cas"`) {
		t.Errorf("body should not contain 'href=\"/ui/cas\"' for user: %s", body)
	}
}
