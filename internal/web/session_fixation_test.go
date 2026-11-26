package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestTOTPLogin_SEC_PERSIST_001_RejectsDuplicateSessionCookies(t *testing.T) {
	w, st := newTestWeb(t)
	_, code := enableTOTPForAdmin(t, w)

	controlReq := httptest.NewRequest(http.MethodGet, "/ui/login/totp", nil)
	controlRec := httptest.NewRecorder()
	w.ServeHTTP(controlRec, controlReq)
	require.Equal(t, http.StatusSeeOther, controlRec.Code)

	var pending string
	for _, cookie := range loginSession(t, w) {
		if cookie.Name == sessionCookieName {
			pending = cookie.Value
		}
	}
	require.NotEmpty(t, pending)

	form := url.Values{"code": {code}, csrfFormField: {"attacker-known-csrf"}}
	req := httptest.NewRequest(http.MethodPost, "/ui/login/totp", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: pending, Path: "/ui"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "victim-session", Path: "/"})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "attacker-known-csrf", Path: "/ui"})
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	require.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/ui/login", rec.Header().Get("Location"))
	_, err := st.GetPendingTwoFactorOperator(context.Background(), pending)
	require.NoError(t, err, "duplicate cookies must not promote the attacker-selected pending session")
	_, err = st.GetOperatorBySession(context.Background(), pending)
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestCompleteTwoFactor_SEC_PERSIST_001_RotatesSessionBearer(t *testing.T) {
	w, st := newTestWeb(t)
	op, err := st.GetOperatorByUsername(context.Background(), testUsername)
	require.NoError(t, err)

	const pending = "pending-session-before-totp"
	require.NoError(t, st.CreateOperatorSession(context.Background(), &models.OperatorSession{
		Token:      pending,
		OperatorID: op.ID,
		State:      models.SessionStatePendingTOTP,
		ExpiresAt:  time.Now().Add(pendingTOTPMaxLife),
	}))

	req := httptest.NewRequest(http.MethodPost, "/ui/login/totp", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: pending})
	rec := httptest.NewRecorder()
	require.NoError(t, w.session.CompleteTwoFactor(rec, req, op.ID))

	var authenticated string
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			authenticated = cookie.Value
		}
	}
	require.NotEmpty(t, authenticated)
	assert.NotEqual(t, pending, authenticated)

	_, err = st.GetOperatorBySession(context.Background(), pending)
	require.ErrorIs(t, err, store.ErrNotFound, "the pre-TOTP bearer must be revoked")
	_, err = st.GetPendingTwoFactorOperator(context.Background(), pending)
	require.ErrorIs(t, err, store.ErrNotFound)
	got, err := st.GetOperatorBySession(context.Background(), authenticated)
	require.NoError(t, err)
	assert.Equal(t, op.ID, got.ID)
}
