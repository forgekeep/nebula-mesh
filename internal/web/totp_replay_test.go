package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// totpConsumeErrStore wraps a real store and forces a non-replay error out of
// ConsumeOperatorTOTPTimestep, leaving every other method (sessions, operator
// lookup) delegating to the embedded store so the login flow still works up to
// the consume.
type totpConsumeErrStore struct {
	store.Store
	err error
}

func (s totpConsumeErrStore) ConsumeOperatorTOTPTimestep(ctx context.Context, id string, ts int64) error {
	return s.err
}

// totpLoginAttempt drives the full password+TOTP login flow with the given
// code and reports whether it ended authenticated (redirect to /ui/).
func totpLoginAttempt(t *testing.T, w *Web, code string) bool {
	t.Helper()
	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/login", nil)
	form := url.Values{
		"username": {testUsername},
		"password": {testPassword},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("password step status = %d", rec.Code)
	}
	cookies = append(cookies, rec.Result().Cookies()...)

	csrfToken, cookies = getCSRFTokenFromCookies(t, w, "/ui/login/totp", cookies)
	form = url.Values{
		"code":  {code},
		"_csrf": {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec.Code == http.StatusSeeOther && rec.Header().Get("Location") == "/ui/"
}

// TestLogin_TOTPCodeNotReplayable pins the one-time property (L5,
// 2026-06-12 audit): a code that authenticated once must be rejected on a
// second login within the same acceptance window, like a consumed recovery
// code. Without the timestep ledger both attempts succeed.
func TestLogin_TOTPCodeNotReplayable(t *testing.T) {
	w, _ := newTestWeb(t)
	_, code := enableTOTPForAdmin(t, w)

	if !totpLoginAttempt(t, w, code) {
		t.Fatal("first login with fresh code failed")
	}
	if totpLoginAttempt(t, w, code) {
		t.Fatal("second login with the SAME code succeeded — TOTP replay within validity window")
	}
}

// TestLogin_TOTPNextWindowCodeStillWorks guards against over-rejection: the
// replay ledger must only block the consumed timestep, not lock the operator
// out of subsequent windows.
func TestLogin_TOTPNextWindowCodeStillWorks(t *testing.T) {
	w, _ := newTestWeb(t)
	secret, code := enableTOTPForAdmin(t, w)

	if !totpLoginAttempt(t, w, code) {
		t.Fatal("first login failed")
	}

	// A code from the next timestep must authenticate. Generate it for
	// now+period and shift the verifier's clock forward to match.
	next := timeNow().Add(totpPeriod * time.Second)
	nextCode, err := totp.GenerateCode(secret, next)
	if err != nil {
		t.Fatal(err)
	}
	orig := timeNow
	timeNow = func() time.Time { return next }
	t.Cleanup(func() { timeNow = orig })

	if !totpLoginAttempt(t, w, nextCode) {
		t.Fatal("login with next-window code failed — replay guard over-rejects")
	}
}

// TestConsumeOperatorTOTPTimestep_CAS pins the store-level contract: strictly
// increasing timesteps consume; the same or an older timestep returns
// ErrTOTPReplayed.
func TestConsumeOperatorTOTPTimestep_CAS(t *testing.T) {
	w, _ := newTestWeb(t)
	ctx := context.Background()
	st := w.store

	if err := st.ConsumeOperatorTOTPTimestep(ctx, "admin-test-id", 1000); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if err := st.ConsumeOperatorTOTPTimestep(ctx, "admin-test-id", 1000); err == nil {
		t.Fatal("same timestep consumed twice")
	} else if !errors.Is(err, store.ErrTOTPReplayed) {
		t.Fatalf("err = %v, want ErrTOTPReplayed", err)
	}
	if err := st.ConsumeOperatorTOTPTimestep(ctx, "admin-test-id", 999); err == nil {
		t.Fatal("older timestep accepted after newer one")
	}
	if err := st.ConsumeOperatorTOTPTimestep(ctx, "admin-test-id", 1001); err != nil {
		t.Fatalf("next timestep: %v", err)
	}
}

// TestLogin_TOTPStoreErrorIs500NotDenial pins that a real store failure during
// timestep consume surfaces as a 500, not a silent "Invalid TOTP code"
// denial — an operator hitting a DB blip must get a distinguishable error,
// and the failure must not look like a wrong code.
func TestLogin_TOTPStoreErrorIs500NotDenial(t *testing.T) {
	baseStore, err := openTestSQLiteStore(t)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { baseStore.Close() })
	if err := baseStore.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := baseStore.CreateOperator(context.Background(), &models.Operator{
		ID: "admin-test-id", Username: testUsername, DisplayName: "Administrator",
		PasswordHash: string(hash), Role: "admin",
	}); err != nil {
		t.Fatal(err)
	}
	_, secret, err := generateTOTPSecret(testUsername)
	if err != nil {
		t.Fatal(err)
	}
	if err := baseStore.SetOperatorTOTP(context.Background(), "admin-test-id", secret, true); err != nil {
		t.Fatal(err)
	}

	wrapped := totpConsumeErrStore{Store: baseStore, err: errors.New("database is locked")}
	w, err := New(wrapped, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	// Password step → pending_totp session.
	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/login", nil)
	form := url.Values{"username": {testUsername}, "password": {testPassword}, "_csrf": {csrfToken}}
	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("password step = %d, want 303", rec.Code)
	}
	cookies = append(cookies, rec.Result().Cookies()...)

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	csrfToken, cookies = getCSRFTokenFromCookies(t, w, "/ui/login/totp", cookies)
	form = url.Values{"code": {code}, "_csrf": {csrfToken}}
	req = httptest.NewRequest(http.MethodPost, "/ui/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("totp step with store error = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Invalid TOTP code") {
		t.Error("store error rendered as an invalid-code denial; must be a 500")
	}
}
