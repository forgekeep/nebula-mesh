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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// failingReader returns the same error on every Read. Used to inject a
// crypto/rand failure into generateCSRFToken via SessionManager.csrfRand,
// so the fail-closed paths in session.go can be exercised.
type failingReader struct{ err error }

func (f *failingReader) Read(_ []byte) (int, error) { return 0, f.err }

// installFailingCSRFRand swaps the SessionManager's CSRF entropy source
// to a reader that always errors, restoring the previous reader on test
// cleanup. The swap is scoped to one SessionManager instance — no
// package-level state — so adding t.Parallel() to other tests stays
// safe.
func installFailingCSRFRand(t *testing.T, sm *SessionManager) {
	t.Helper()
	prev := sm.csrfRand
	sm.SetCSRFRandForTest(&failingReader{err: errors.New("simulated rand failure")})
	t.Cleanup(func() { sm.SetCSRFRandForTest(prev) })
}

// assertNoSetCookie verifies the response did NOT emit a Set-Cookie for
// the given name. With the deferred-SetCookie restructure, fail-closed
// paths must not touch the response at all — the browser keeps whatever
// cookie state it had before the failed request.
func assertNoSetCookie(t *testing.T, rec *httptest.ResponseRecorder, name string) {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			t.Fatalf("response unexpectedly set cookie %q (Value=%q, MaxAge=%d) on the fail-closed path", name, c.Value, c.MaxAge)
		}
	}
}

// TestLogin_FailingRand_NoSessionCreated pins the fail-closed behavior of
// session.Login when generateCSRFToken errors during rotation. With both
// tokens generated before any DB write, the failure path leaves nothing
// behind: no session row, no Set-Cookie, the response is clean.
func TestLogin_FailingRand_NoSessionCreated(t *testing.T) {
	w, _ := newTestWeb(t)
	installFailingCSRFRand(t, w.session)

	loginRec := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/ui/login", nil)
	result, ok, err := w.session.Login(loginRec, loginReq, testUsername, testPassword)
	require.Error(t, err, "Login must surface CSRF rotation failure")
	assert.False(t, ok, "Login must not report success when rotation fails")
	assert.Nil(t, result.Operator, "no operator should be returned on fail-closed path")

	// CSRF rotation runs before CreateOperatorSession in the new
	// shape, so a failed rotation never reaches the DB write or the
	// Set-Cookie calls. Asserting the cookies are absent transitively
	// asserts the session row is absent — they're emitted together.
	assertNoSetCookie(t, loginRec, sessionCookieName)
	assertNoSetCookie(t, loginRec, csrfCookieName)
}

// TestStartAuthenticatedSession_FailingRand_NoSessionCreated pins
// fail-closed on the OIDC entry point. The fail-closed path leaves no
// session row and no cookies.
func TestStartAuthenticatedSession_FailingRand_NoSessionCreated(t *testing.T) {
	w, st := newTestWeb(t)

	op := &models.Operator{
		ID:           "oidc-fail-op",
		Username:     "oidc-fail",
		PasswordHash: "$2a$12$abcdefghijklmnopqrstuvwxyzABCDEF",
		Status:       models.OperatorStatusActive,
	}
	require.NoError(t, st.CreateOperator(context.Background(), op))

	installFailingCSRFRand(t, w.session)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ui/oidc/callback", nil)
	err := w.session.StartAuthenticatedSession(rec, req, op)
	require.Error(t, err, "StartAuthenticatedSession must surface CSRF rotation failure")

	assertNoSetCookie(t, rec, sessionCookieName)
	assertNoSetCookie(t, rec, csrfCookieName)
}

// TestCompleteTwoFactor_FailingRand_LeavesPendingIntact pins fail-closed
// on the TOTP-promotion path. The pending session was NOT promoted
// (generateCSRFToken runs before PromoteOperatorSession), so the
// pending_totp row remains alive for its remaining TTL — the user can
// retry the second factor without re-entering the password.
func TestCompleteTwoFactor_FailingRand_LeavesPendingIntact(t *testing.T) {
	w, st := newTestWeb(t)

	op, err := st.GetOperatorByUsername(context.Background(), testUsername)
	require.NoError(t, err)

	sessionToken := "test-pending-totp-session"
	require.NoError(t, st.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      sessionToken,
		OperatorID: op.ID,
		State:      models.SessionStatePendingTOTP,
		ExpiresAt:  time.Now().Add(pendingTOTPMaxLife),
	}))

	installFailingCSRFRand(t, w.session)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ui/login/totp", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	err = w.session.CompleteTwoFactor(rec, req, op.ID)
	require.Error(t, err, "CompleteTwoFactor must surface CSRF rotation failure")

	// Pending row must remain alive (not promoted, not deleted).
	pendOp, pendErr := st.GetPendingTwoFactorOperator(context.Background(), sessionToken)
	require.NoError(t, pendErr, "pending_totp session must survive a CSRF rotation failure so the user can retry")
	assert.Equal(t, op.ID, pendOp.ID)

	// Belt-and-suspenders: it must NOT be authenticated either.
	_, authErr := st.GetOperatorBySession(context.Background(), sessionToken)
	require.ErrorIs(t, authErr, store.ErrNotFound,
		"pending_totp session must not be visible via the authenticated-session lookup")

	assertNoSetCookie(t, rec, sessionCookieName)
	assertNoSetCookie(t, rec, csrfCookieName)
}

// TestCSRF_FailingRand_LoginHandler_500AndNoFallbackCookie pins end-to-end
// handler behavior: a failing-rand POST /ui/login renders 500 and emits
// no Set-Cookie that re-asserts the pre-rotation CSRF value. The
// Warn-and-continue regression would have left the pre-rotation CSRF
// cookie alive (since rotation never overwrote it). The deferred-SetCookie
// restructure makes this even tighter: no Set-Cookie at all on the
// failure path.
func TestCSRF_FailingRand_LoginHandler_500AndNoFallbackCookie(t *testing.T) {
	w, _ := newTestWeb(t)

	getRec := httptest.NewRecorder()
	w.ServeHTTP(getRec, httptest.NewRequest(http.MethodGet, "/ui/login", nil))

	var preRotationCSRF *http.Cookie
	for _, c := range getRec.Result().Cookies() {
		if c.Name == csrfCookieName {
			preRotationCSRF = c
			break
		}
	}
	require.NotNil(t, preRotationCSRF, "GET /ui/login should set a CSRF cookie")

	installFailingCSRFRand(t, w.session)

	form := url.Values{
		"username":    {testUsername},
		"password":    {testPassword},
		csrfFormField: {preRotationCSRF.Value},
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.AddCookie(preRotationCSRF)
	loginRec := httptest.NewRecorder()
	w.ServeHTTP(loginRec, loginReq)

	assert.Equal(t, http.StatusInternalServerError, loginRec.Code,
		"handler must render 500 when CSRF rotation fails")

	assertNoSetCookie(t, loginRec, sessionCookieName)
	// No Set-Cookie for nebula_csrf either: the failure path runs
	// before any rotation cookie is emitted, and no fallback restates
	// the pre-rotation value.
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == csrfCookieName {
			assert.NotEqual(t, preRotationCSRF.Value, c.Value,
				"fail-closed must not re-emit the pre-rotation CSRF value")
		}
	}
}
