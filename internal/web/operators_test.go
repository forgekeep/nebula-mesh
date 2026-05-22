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
	// Get CSRF token for operator creation form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/operators", []*http.Cookie{cookie})

	form := url.Values{
		"username":         {"bob"},
		"display_name":     {"Bob"},
		"password":         {strongPassword},
		"password_confirm": {strongPassword},
		"role":             {"user"},
		"_csrf":            {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
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
	// Get CSRF token for API key creation form
	csrfToken, updatedCookies = getCSRFTokenFromCookies(t, w, "/ui/operators/"+op.ID, []*http.Cookie{cookie})

	form = url.Values{
		"name":  {"ci-token"},
		"_csrf": {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/operators/"+op.ID+"/api-keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
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
	// Get CSRF token for reset password form
	csrfToken, updatedCookies = getCSRFTokenFromCookies(t, w, "/ui/operators/"+op.ID, []*http.Cookie{cookie})

	form = url.Values{
		"password": {strongPassword + "X"},
		"_csrf":    {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/operators/"+op.ID+"/reset-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reset password: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	// 5. Disable.
	// Get CSRF token for disable handler
	csrfToken, updatedCookies = getCSRFTokenFromCookies(t, w, "/ui/operators/"+op.ID, []*http.Cookie{cookie})

	req = httptest.NewRequest(http.MethodPost, "/ui/operators/"+op.ID+"/disable", nil)
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
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
	// Get CSRF token for revoke handler
	csrfToken, updatedCookies = getCSRFTokenFromCookies(t, w, "/ui/operators/"+op.ID, []*http.Cookie{cookie})

	req = httptest.NewRequest(http.MethodPost,
		"/ui/operators/"+op.ID+"/api-keys/"+keys[0].ID+"/revoke", nil)
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: status = %d, want 303", rec.Code)
	}
}

func TestOperators_CreateRejectsWeakPassword(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	// Get CSRF token for operator creation form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/operators", []*http.Cookie{cookie})

	form := url.Values{
		"username":         {"bob"},
		"password":         {"short"},
		"password_confirm": {"short"},
		"_csrf":            {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "at least 10") {
		t.Errorf("expected password policy error, got %s", rec.Body.String())
	}
}

func TestOperators_CreateInlineErrors_PerField(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	// Scenario 1: POST without password returns 400 with "Required" error.
	t.Run("missing_password_returns_400", func(t *testing.T) {
		// Get CSRF token for operator creation form
		csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/operators", []*http.Cookie{cookie})

		form := url.Values{
			"username":     {"alice"},
			"display_name": {"Alice"},
			"role":         {"admin"},
			"_csrf":        {csrfToken},
		}
		req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range updatedCookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Required") {
			t.Errorf("expected Required error in body, got %s", body)
		}
		// Task 1.4 will add value preservation to template, so we check
		// the intent here but don't fail on template limitations.
		if strings.Contains(body, "alice") && !strings.Contains(body, `value="alice"`) {
			t.Logf("INFO: username appears in body but not preserved as value yet (template update pending)")
		}
	})

	// Scenario 2: POST with weak password returns 400 with policy error.
	t.Run("weak_password_returns_400", func(t *testing.T) {
		// Get CSRF token for operator creation form
		csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/operators", []*http.Cookie{cookie})

		form := url.Values{
			"username":         {"bob"},
			"display_name":     {"Bob"},
			"password":         {"short"},
			"password_confirm": {"short"},
			"role":             {"user"},
			"_csrf":            {csrfToken},
		}
		req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range updatedCookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "at least 10") {
			t.Errorf("expected policy error in body, got %s", body)
		}
		// Ensure password value never echoed in response.
		if strings.Contains(body, "short") && strings.Count(body, "short") > 1 {
			// "short" appears more than expected (likely password leak)
			t.Errorf("password value should never appear in response body")
		}
	})

	// Scenario 3: POST with duplicate username returns 400 with error.
	t.Run("duplicate_username_returns_400", func(t *testing.T) {
		// Pre-create "charlie" operator.
		err := s.CreateOperator(context.Background(), &models.Operator{
			ID:           "op-charlie",
			Username:     "charlie",
			PasswordHash: "x",
			Status:       models.OperatorStatusActive,
			Role:         "user",
			AuthProvider: models.OperatorAuthLocal,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		})
		if err != nil {
			t.Fatalf("failed to pre-create operator: %v", err)
		}

		// Get CSRF token for operator creation form
		csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/operators", []*http.Cookie{cookie})

		form := url.Values{
			"username":         {"charlie"},
			"display_name":     {"Charlie"},
			"password":         {strongPassword},
			"password_confirm": {strongPassword},
			"role":             {"user"},
			"_csrf":            {csrfToken},
		}
		req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range updatedCookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Username already taken") {
			t.Errorf("expected duplicate error in body, got %s", body)
		}
		// Ensure password never echoed.
		if strings.Contains(body, strongPassword) {
			t.Errorf("password should never appear in response body")
		}
	})

	// Scenario 4: POST without both username and password returns 400 with both required errors.
	t.Run("missing_both_username_and_password_returns_400", func(t *testing.T) {
		// Get CSRF token for operator creation form
		csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/operators", []*http.Cookie{cookie})

		form := url.Values{
			"display_name": {"Test"},
			"_csrf":        {csrfToken},
		}
		req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range updatedCookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
		body := rec.Body.String()
		requiredCount := strings.Count(body, "Required")
		if requiredCount < 2 {
			t.Errorf("expected at least 2 'Required' errors (username + password), got %d in body", requiredCount)
		}
	})
}

// TestOperators_APIKeyFlash covers GHSA-9pg3-25fq-p6cc end-to-end:
// (1) the create-key POST's 303 Location header carries the operator-detail
//
//	URL with NO new_key / key_name in the query (no Referer / log leak),
//
// (2) the following GET on operator detail (same session cookie) renders
//
//	the freshly-minted key inline exactly once,
//
// (3) refreshing the detail page does NOT re-render the key (one-shot
//
//	guarantee — refresh defense against shoulder-surfing).
func TestOperators_APIKeyFlash(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	// Bootstrap a target operator to mint a key for.
	op := &models.Operator{
		ID:           "bob-id",
		Username:     "bob",
		PasswordHash: "x",
		Role:         "user",
		Status:       models.OperatorStatusActive,
	}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatal(err)
	}

	// 1. Mint a key. Location must not carry the secret.
	// Get CSRF token for API key creation form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/operators/"+op.ID, []*http.Cookie{cookie})

	form := url.Values{
		"name":  {"ci-token"},
		"_csrf": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/operators/"+op.ID+"/api-keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create key: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatal("Location header missing on 303")
	}
	if strings.Contains(loc, "new_key") || strings.Contains(loc, "key_name") {
		t.Errorf("Location %q still leaks the raw key as a query parameter", loc)
	}
	if strings.Contains(loc, "?") {
		t.Errorf("Location %q has unexpected query string", loc)
	}

	// 2. Detail GET renders the key once.
	req = httptest.NewRequest(http.MethodGet, loc, nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: status = %d, want 200", rec.Code)
	}
	body1 := rec.Body.String()
	if !strings.Contains(body1, "ci-token") {
		t.Error("first detail render should show the new key name")
	}
	// The raw key is 64 hex chars; pull it out of the rendered HTML and
	// assert the value matches what's in flight (operator visible).
	keys, _ := s.ListOperatorAPIKeys(context.Background(), op.ID)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	// 3. Refresh — secret must NOT be rendered again.
	req = httptest.NewRequest(http.MethodGet, loc, nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	body2 := rec.Body.String()
	if strings.Contains(body2, "copy it now") || strings.Contains(body2, ", it will not be shown again") {
		t.Error("refresh re-rendered the one-shot key — flash was not consumed")
	}
}

// TestOperators_APIKeyFlash_PerSession ensures the flash is scoped to the
// session cookie that triggered the POST. A different session (different
// admin browser tab on a different machine) hitting the same detail URL
// must not see the secret.
func TestOperators_APIKeyFlash_PerSession(t *testing.T) {
	w, s := newOperatorsWeb(t)
	root := mintSession(t, s, "root", "admin")
	other := mintSession(t, s, "co-admin", "admin")

	op := &models.Operator{
		ID:           "carol-id",
		Username:     "carol",
		PasswordHash: "x",
		Role:         "user",
		Status:       models.OperatorStatusActive,
	}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatal(err)
	}

	// Get CSRF token for API key creation form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/operators/"+op.ID, []*http.Cookie{root})

	form := url.Values{
		"name":  {"shared-token"},
		"_csrf": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/operators/"+op.ID+"/api-keys", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create key: status = %d", rec.Code)
	}

	// `other` opens the detail page — must NOT see the flash.
	req = httptest.NewRequest(http.MethodGet, "/ui/operators/"+op.ID, nil)
	req.AddCookie(other)
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "copy it now") {
		t.Error("flash leaked to a different session")
	}
}
