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

func newOperatorsWeb(t *testing.T) (*Web, store.Store) {
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

func mintSession(t *testing.T, s store.Store, username, role string) *http.Cookie {
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

func TestOperators_NonAdmin_403(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")

	for _, path := range []string{
		"/ui/operators",
		"/ui/operators/new",
		"/ui/operators/op-someone",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status = %d, want 403", path, rec.Code)
		}
	}
}

func TestOperators_AdminLifecycle(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	// 1. Create.
	form := url.Values{
		"username":         {"bob"},
		"display_name":     {"Bob"},
		"password":         {strongPassword},
		"password_confirm": {strongPassword},
		"role":             {"user"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	op, err := s.GetOperatorByUsername(context.Background(), "bob")
	if err != nil {
		t.Fatalf("bob not created: %v", err)
	}

	// 2. Detail page lists no keys yet.
	req = httptest.NewRequest(http.MethodGet, "/ui/operators/"+op.ID, nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: status = %d, want 200", rec.Code)
	}

	// 3. Create an API key.
	form = url.Values{"name": {"ci-token"}}
	req = httptest.NewRequest(http.MethodPost, "/ui/operators/"+op.ID+"/api-keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create key: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
	keys, err := s.ListOperatorAPIKeys(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Name != "ci-token" {
		t.Fatalf("expected 1 key named ci-token, got %+v", keys)
	}

	// 4. Reset password.
	form = url.Values{"password": {strongPassword + "X"}}
	req = httptest.NewRequest(http.MethodPost, "/ui/operators/"+op.ID+"/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reset password: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	// 5. Disable.
	req = httptest.NewRequest(http.MethodPost, "/ui/operators/"+op.ID+"/disable", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("disable: status = %d, want 303", rec.Code)
	}
	got, _ := s.GetOperator(context.Background(), op.ID)
	if got.Status != models.OperatorStatusDisabled {
		t.Errorf("status = %q, want disabled", got.Status)
	}

	// 6. Revoke API key.
	req = httptest.NewRequest(http.MethodPost,
		"/ui/operators/"+op.ID+"/api-keys/"+keys[0].ID+"/revoke", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: status = %d, want 303", rec.Code)
	}
}

func TestOperators_CreateRejectsWeakPassword(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	form := url.Values{
		"username":         {"bob"},
		"password":         {"short"},
		"password_confirm": {"short"},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "at least 10") {
		t.Errorf("expected password policy error, got %s", rec.Body.String())
	}
}
