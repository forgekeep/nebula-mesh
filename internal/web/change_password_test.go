package web

import (
	"context"
	"errors"
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

const oldPassword = "Old-Password!1Strong"

// passwordOperator creates a local operator with a real bcrypt hash of
// oldPassword plus an authenticated session, returning the current-session
// cookie. Used by the self-service password-change tests (#259).
func passwordOperator(t *testing.T, s store.Store, username, token string) (*models.Operator, *http.Cookie) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	op := &models.Operator{
		ID:           "op-" + username,
		Username:     username,
		PasswordHash: string(hash),
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      token,
		OperatorID: op.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return op, &http.Cookie{Name: "nebula_session", Value: token}
}

func postChangePassword(t *testing.T, w *Web, auth *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/profile", []*http.Cookie{auth})
	form.Set("_csrf", csrfToken)
	req := httptest.NewRequest(http.MethodPost, "/ui/profile/change-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec
}

func TestChangePassword_HappyPath(t *testing.T) {
	w, s := newOperatorsWeb(t)
	op, auth := passwordOperator(t, s, "erin", "erin-current")

	// A second, "other-device" session that must be revoked by the change.
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      "erin-other",
		OperatorID: op.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	newPass := oldPassword + "-new9"
	rec := postChangePassword(t, w, auth, url.Values{
		"old_password":         {oldPassword},
		"new_password":         {newPass},
		"new_password_confirm": {newPass},
	})
	if rec.Code != http.StatusOK && rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 200/303; body=%s", rec.Code, rec.Body.String())
	}

	// Password actually changed.
	got, err := s.GetOperator(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte(newPass)) != nil {
		t.Error("new password does not verify against stored hash")
	}

	// Current session survives; other session revoked.
	if _, err := s.GetOperatorBySession(context.Background(), "erin-current"); err != nil {
		t.Errorf("current session should survive, got %v", err)
	}
	if _, err := s.GetOperatorBySession(context.Background(), "erin-other"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("other session should be revoked, got err=%v", err)
	}
}

func TestChangePassword_WrongOldPassword(t *testing.T) {
	w, s := newOperatorsWeb(t)
	op, auth := passwordOperator(t, s, "frank", "frank-current")

	newPass := oldPassword + "-new9"
	rec := postChangePassword(t, w, auth, url.Values{
		"old_password":         {"totally-wrong-old"},
		"new_password":         {newPass},
		"new_password_confirm": {newPass},
	})
	if rec.Code == http.StatusSeeOther {
		t.Fatalf("wrong old password should not redirect as success; status=%d", rec.Code)
	}

	// Password unchanged: old still verifies.
	got, err := s.GetOperator(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte(oldPassword)) != nil {
		t.Error("password should be unchanged after wrong old password")
	}
}

func TestChangePassword_WeakNewPassword(t *testing.T) {
	w, s := newOperatorsWeb(t)
	op, auth := passwordOperator(t, s, "grace", "grace-current")

	rec := postChangePassword(t, w, auth, url.Values{
		"old_password":         {oldPassword},
		"new_password":         {"short"},
		"new_password_confirm": {"short"},
	})
	if rec.Code == http.StatusSeeOther {
		t.Fatalf("weak new password should not redirect as success; status=%d", rec.Code)
	}
	got, _ := s.GetOperator(context.Background(), op.ID)
	if bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte(oldPassword)) != nil {
		t.Error("password should be unchanged after weak new password")
	}
}

func TestChangePassword_MismatchedConfirm(t *testing.T) {
	w, s := newOperatorsWeb(t)
	op, auth := passwordOperator(t, s, "heidi", "heidi-current")

	newPass := oldPassword + "-new9"
	rec := postChangePassword(t, w, auth, url.Values{
		"old_password":         {oldPassword},
		"new_password":         {newPass},
		"new_password_confirm": {newPass + "X"},
	})
	if rec.Code == http.StatusSeeOther {
		t.Fatalf("mismatched confirm should not redirect as success; status=%d", rec.Code)
	}
	got, _ := s.GetOperator(context.Background(), op.ID)
	if bcrypt.CompareHashAndPassword([]byte(got.PasswordHash), []byte(oldPassword)) != nil {
		t.Error("password should be unchanged after mismatched confirm")
	}
}

// TestProfile_ChangePasswordForm_LocalOnly verifies the form renders for a
// local operator and is hidden for an OIDC operator (#259).
func TestProfile_ChangePasswordForm_LocalOnly(t *testing.T) {
	w, s := newOperatorsWeb(t)
	_, localAuth := passwordOperator(t, s, "ivan", "ivan-current")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ui/profile", nil)
	req.AddCookie(localAuth)
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "change-password") {
		t.Error("local operator profile should render the change-password form")
	}

	// OIDC operator: no local password, form hidden.
	oidc := &models.Operator{
		ID:           "op-judy",
		Username:     "judy",
		PasswordHash: "oidc",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthOIDC,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(context.Background(), oidc); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      "judy-current",
		OperatorID: oidc.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/ui/profile", nil)
	req.AddCookie(&http.Cookie{Name: "nebula_session", Value: "judy-current"})
	w.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "change-password") {
		t.Error("OIDC operator profile should not render the change-password form")
	}
}
