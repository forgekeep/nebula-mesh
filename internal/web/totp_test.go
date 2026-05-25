package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestGenerateAndVerifyTOTP(t *testing.T) {
	_, secret, err := generateTOTPSecret("alice")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = time.Now })

	if !verifyTOTP(secret, code) {
		t.Error("expected verifyTOTP to accept current code")
	}
	if verifyTOTP(secret, "000000") {
		t.Error("verifyTOTP accepted bogus code")
	}
}

func TestGenerateRecoveryCodes_HashesMatch(t *testing.T) {
	codes, hashes, err := generateRecoveryCodes(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 5 || len(hashes) != 5 {
		t.Fatalf("got %d codes / %d hashes", len(codes), len(hashes))
	}
	for i, c := range codes {
		if hashRecoveryCode(c) != hashes[i] {
			t.Errorf("hash mismatch for code %d", i)
		}
		if hashRecoveryCode(strings.ToLower(c)) != hashes[i] {
			t.Errorf("case-insensitive normalization broke for code %d", i)
		}
	}
}

// enableTOTPForAdmin programmatically enables TOTP for the seeded admin user
// and returns the secret and a valid current code.
func enableTOTPForAdmin(t *testing.T, w *Web) (secret, code string) {
	t.Helper()
	_, secret, err := generateTOTPSecret("admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.store.SetOperatorTOTP(context.Background(), "admin-test-id", secret, true); err != nil {
		t.Fatal(err)
	}
	code, err = totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return secret, code
}

func TestLogin_TOTPFlow(t *testing.T) {
	w, _ := newTestWeb(t)
	_, code := enableTOTPForAdmin(t, w)

	// Step 1: password
	// Get CSRF token for login form
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
		t.Fatalf("step1 status = %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/ui/login/totp" {
		t.Errorf("step1 redirect = %q, want /ui/login/totp", loc)
	}
	cookies = append(cookies, rec.Result().Cookies()...)

	// Visiting /ui/ should still redirect to login because session is pending_totp
	req = httptest.NewRequest(http.MethodGet, "/ui/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("pending session protected = %d, want 303", rec.Code)
	}

	// Step 2: TOTP code
	// Get CSRF token for TOTP login form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/login/totp", cookies)

	form = url.Values{
		"code":  {code},
		"_csrf": {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("step2 status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != "/ui/" {
		t.Errorf("step2 redirect = %q", loc)
	}

	// Now session should be fully authenticated
	req = httptest.NewRequest(http.MethodGet, "/ui/", nil)
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("authenticated dashboard status = %d", rec.Code)
	}
}

func TestLogin_TOTPInvalidCode(t *testing.T) {
	w, _ := newTestWeb(t)
	_, _ = enableTOTPForAdmin(t, w)

	// Get CSRF token for login form
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
	cookies = append(cookies, rec.Result().Cookies()...)

	// Get CSRF token for TOTP form
	csrfToken, cookies = getCSRFTokenFromCookies(t, w, "/ui/login/totp", cookies)

	form = url.Values{
		"code":  {"000000"},
		"_csrf": {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Invalid TOTP code") {
		t.Errorf("expected Invalid TOTP code error; body=%s", rec.Body.String())
	}
}

func TestLogin_TOTPRecoveryCode(t *testing.T) {
	w, _ := newTestWeb(t)
	_, _ = enableTOTPForAdmin(t, w)

	// Seed a recovery code we know.
	plainCode := "RECOVER123"
	if err := w.store.ReplaceOperatorRecoveryCodes(context.Background(), "admin-test-id", []string{hashRecoveryCode(plainCode)}); err != nil {
		t.Fatal(err)
	}

	// Get CSRF token for login form
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
	cookies = append(cookies, rec.Result().Cookies()...)

	// Get CSRF token for TOTP form
	csrfToken, cookies = getCSRFTokenFromCookies(t, w, "/ui/login/totp", cookies)

	form = url.Values{
		"recovery_code": {plainCode},
		"_csrf":         {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("recovery code login status = %d; body=%s", rec.Code, rec.Body.String())
	}

	// Second attempt with same code should fail (single-use)
	// Get CSRF token for login form
	csrfToken, cookies = getCSRFTokenFromCookies(t, w, "/ui/login", nil)

	form = url.Values{
		"username": {testUsername},
		"password": {testPassword},
		"_csrf":    {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	cookies = append(cookies, rec.Result().Cookies()...)

	// Get CSRF token for TOTP form
	csrfToken, cookies = getCSRFTokenFromCookies(t, w, "/ui/login/totp", cookies)

	form = url.Values{
		"recovery_code": {plainCode},
		"_csrf":         {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Invalid TOTP code") {
		t.Errorf("expected reuse to fail; body=%s", rec.Body.String())
	}
}

func TestTwoFASetupAndEnable(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	// Setup
	csrfToken, updatedSetupCookies := getCSRFTokenFromCookies(t, w, "/ui/2fa", cookies)
	req := httptest.NewRequest(http.MethodPost, "/ui/2fa/setup", nil)
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range updatedSetupCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("setup status = %d", rec.Code)
	}
	// Use updated cookies for subsequent requests
	cookies = updatedSetupCookies
	body := rec.Body.String()
	if !strings.Contains(body, "otpauth://") {
		t.Errorf("setup page should contain otpauth URL; body=%s", body)
	}

	// Reload operator and generate code
	op, _ := s.GetOperator(context.Background(), "admin-test-id")
	if op.TOTPSecret == "" {
		t.Fatal("totp secret not stored after setup")
	}
	if op.TOTPEnabled {
		t.Error("totp_enabled should still be false after setup")
	}
	code, err := totp.GenerateCode(op.TOTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Enable
	// Get CSRF token for 2FA enable form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/2fa", cookies)

	form := url.Values{
		"code":  {code},
		"_csrf": {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/2fa/enable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable status = %d; body=%s", rec.Code, rec.Body.String())
	}
	body = rec.Body.String()
	if !strings.Contains(body, "Recovery codes") {
		t.Error("recovery codes block missing after enable")
	}

	op, _ = s.GetOperator(context.Background(), "admin-test-id")
	if !op.TOTPEnabled {
		t.Error("totp_enabled should be true after enable")
	}

	// Audit log entry recorded
	entries, _ := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
	found := false
	for _, e := range entries {
		if e.Action == "operator.2fa.enabled" {
			found = true
		}
	}
	if !found {
		t.Error("audit entry operator.2fa.enabled missing")
	}
}

func TestTwoFADisable_RequiresPassword(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	// Pre-enable TOTP
	_, _ = enableTOTPForAdmin(t, w)

	// Wrong password — should fail
	// Get CSRF token for 2FA disable form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/2fa", cookies)

	form := url.Values{
		"password": {"wrong"},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/2fa/disable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Password does not match") {
		t.Error("expected password mismatch error")
	}
	op, _ := s.GetOperator(context.Background(), "admin-test-id")
	if !op.TOTPEnabled {
		t.Error("TOTP should still be enabled after failed disable")
	}

	// Correct password — should succeed
	// Get CSRF token for 2FA disable form
	csrfToken, updatedCookies = getCSRFTokenFromCookies(t, w, "/ui/2fa", cookies)

	form = url.Values{
		"password": {testPassword},
		"_csrf":    {csrfToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/ui/2fa/disable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("disable status = %d", rec.Code)
	}

	op, _ = s.GetOperator(context.Background(), "admin-test-id")
	if op.TOTPEnabled {
		t.Error("TOTP should be disabled after successful disable")
	}
	codes, _ := s.ListOperatorRecoveryCodes(context.Background(), "admin-test-id")
	if len(codes) != 0 {
		t.Error("recovery codes should be cleared after disable")
	}
}

func TestTwoFAAuditEntries(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	_, _ = enableTOTPForAdmin(t, w)

	// Trigger failed disable
	// Get CSRF token for 2FA disable form
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/2fa", cookies)

	form := url.Values{
		"password": {"wrong"},
		"_csrf":    {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/2fa/disable", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	_ = rec

	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "operator.2fa.disable_failed" {
			found = true
		}
	}
	if !found {
		t.Error("audit entry operator.2fa.disable_failed not recorded")
	}

	// Sanity check: operator still has TOTP enabled
	op, _ := s.GetOperator(context.Background(), "admin-test-id")
	if !op.TOTPEnabled {
		t.Error("totp should still be enabled")
	}
	_ = op
	_ = models.OperatorStatusActive
}

func TestTwoFA_PageIncludesCSRFTokenInForms(t *testing.T) {
	w, s := newTestWeb(t)

	// Create an authenticated session.
	op := &models.Operator{
		ID:           "alice-id",
		Username:     "alice",
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	tok := "session-alice"
	if err := s.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      tok,
		OperatorID: op.ID,
		State:      models.SessionStateAuthenticated,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{Name: "nebula_session", Value: tok}

	// GET /ui/2fa to view the page.
	req := httptest.NewRequest(http.MethodGet, "/ui/2fa", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Verify CSRF token is present in all forms.
	// There are multiple forms on the 2FA page depending on state, but each should have {{ csrfField }}.
	formCount := strings.Count(body, `<form method="POST"`)
	csrfCount := strings.Count(body, `name="_csrf"`)
	if formCount == 0 {
		t.Errorf("expected at least 1 POST form in 2FA page")
	}
	if csrfCount == 0 {
		t.Errorf("expected CSRF token input in 2FA page forms; body=%s", body)
	}
	if csrfCount < formCount {
		t.Errorf("not all forms have CSRF tokens: forms=%d, csrf=%d", formCount, csrfCount)
	}
}
