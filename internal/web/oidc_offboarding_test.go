package web

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

const offboardingTestSession = "previous-oidc-session"
const offboardingTestKey = "previous-oidc-api-key"

func seedOffboardingOperator(t *testing.T, s store.Store, issuer string) *models.Operator {
	t.Helper()
	op := &models.Operator{
		ID: "oidc-operator", Username: "oidc-operator", PasswordHash: "oidc",
		AuthProvider: models.OperatorAuthOIDC, Role: models.OperatorRoleAdmin,
		OIDCIssuer: issuer, OIDCSubject: "example-subject",
	}
	require.NoError(t, s.CreateOperator(t.Context(), op))
	require.NoError(t, s.CreateOperatorSession(t.Context(), &models.OperatorSession{
		Token: offboardingTestSession, OperatorID: op.ID, ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, s.CreateOperatorAPIKey(t.Context(), &models.OperatorAPIKey{
		ID: "oidc-key", OperatorID: op.ID, Name: "test",
	}, offboardingTestKey))
	return op
}

func TestOIDCOffboarding_SEC_PERSIST_001_Webhook(t *testing.T) {
	w, s := newTestWeb(t)
	idp := setupOIDCServer(t)
	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{})
	w.WithOIDC(o)
	key := bytes.Repeat([]byte{42}, sha256.Size)
	require.NoError(t, w.WithOIDCOffboarding(hex.EncodeToString(key)))
	op := seedOffboardingOperator(t, s, idp.Issuer())
	event := oidcOffboardingRequest{
		EventID: "membership-change", Issuer: idp.Issuer(), Audience: o.cfg.ClientID,
		Subject: op.OIDCSubject, IssuedAt: time.Now().Unix(),
	}

	deliver := func(event oidcOffboardingRequest, key []byte, scheme string) int {
		t.Helper()
		data, err := json.Marshal(event)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, scheme+"://nebula.example"+oidcOffboardingPath, bytes.NewReader(data))
		req.Header.Set("Content-Type", "application/json")
		if key != nil {
			mac := hmac.New(sha256.New, key)
			_, _ = mac.Write(data)
			req.Header.Set(oidcOffboardingSignature, "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		return rec.Code
	}

	require.Equal(t, http.StatusUpgradeRequired, deliver(event, key, "http"))
	require.Equal(t, http.StatusUnauthorized, deliver(event, nil, "https"))
	require.Equal(t, http.StatusUnauthorized, deliver(event, []byte("untrusted key"), "https"))
	wrongAudience := event
	wrongAudience.Audience = "other-application"
	require.Equal(t, http.StatusBadRequest, deliver(wrongAudience, key, "https"))
	old := event
	old.IssuedAt = time.Now().Add(-time.Hour).Unix()
	require.Equal(t, http.StatusBadRequest, deliver(old, key, "https"))
	unknown := event
	unknown.EventID = "other-membership-change"
	unknown.Subject = "different-subject"
	require.Equal(t, http.StatusNoContent, deliver(unknown, key, "https"))
	_, err := s.GetOperatorBySession(t.Context(), offboardingTestSession)
	require.NoError(t, err)

	require.Equal(t, http.StatusNoContent, deliver(event, key, "https"))
	_, err = s.GetOperatorBySession(t.Context(), offboardingTestSession)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, _, err = s.GetOperatorByAPIKey(t.Context(), offboardingTestKey)
	require.ErrorIs(t, err, store.ErrNotFound)
	require.ErrorIs(t, s.CreateOperatorAPIKey(t.Context(),
		&models.OperatorAPIKey{ID: "disabled-key", OperatorID: op.ID, Name: "test"}, "new-key"),
		store.ErrNotFound)

	require.NoError(t, s.EnableOperator(t.Context(), op.ID))
	require.Equal(t, http.StatusNoContent, deliver(event, key, "https"))
	current, err := s.GetOperator(t.Context(), op.ID)
	require.NoError(t, err)
	require.Equal(t, models.OperatorStatusActive, current.Status)
	_, _, err = s.GetOperatorByAPIKey(t.Context(), offboardingTestKey)
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestOIDCOffboarding_SEC_PERSIST_001_ConfirmedCallbackDenial(t *testing.T) {
	w, s := newTestWeb(t)
	idp := setupOIDCServer(t)
	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{AllowedGroups: []string{"operators"}})
	w.WithOIDC(o)
	op := seedOffboardingOperator(t, s, idp.Issuer())

	idp.NextIDToken(map[string]any{"sub": op.OIDCSubject, "aud": "test-client"})
	response := driveCallback(t, o, "missing-group-claim", "first-code")
	require.Equal(t, http.StatusForbidden, response.Code)
	_, err := s.GetOperatorBySession(t.Context(), offboardingTestSession)
	require.NoError(t, err, "a missing claim is not a confirmed removal")

	idp.NextIDToken(map[string]any{"sub": op.OIDCSubject, "aud": "test-client", "groups": []string{}})
	response = driveCallback(t, o, "explicit-group-claim", "second-code")
	require.Equal(t, http.StatusForbidden, response.Code)
	_, err = s.GetOperatorBySession(t.Context(), offboardingTestSession)
	require.ErrorIs(t, err, store.ErrNotFound)
	_, _, err = s.GetOperatorByAPIKey(t.Context(), offboardingTestKey)
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestOIDCOffboardingRequiresScopedKey(t *testing.T) {
	w, _ := newTestWeb(t)
	require.Error(t, w.WithOIDCOffboarding(strings.Repeat("42", sha256.Size)))
	w.WithOIDC(&OIDC{})
	require.Error(t, w.WithOIDCOffboarding("short"))
}
