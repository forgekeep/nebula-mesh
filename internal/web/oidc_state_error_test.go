package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/config"
)

// TestOIDC_HandleCallback_ErrorParamClearsFlowCookie verifies that an IdP
// denial clears the browser-held transaction and creates no local session.
func TestOIDC_HandleCallback_ErrorParamClearsFlowCookie(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServer(t)
	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{
		AllowedEmails: []string{"alice@example.com"},
		DefaultRole:   "user",
	})

	const stateValue = "state-replay-defense"

	// Drive a callback with ?error=access_denied.
	errRec := driveCallbackWithError(t, o, stateValue, "access_denied")
	if errRec.Code != http.StatusBadRequest {
		t.Errorf("error-path status = %d, want 400 (body: %s)", errRec.Code, errRec.Body.String())
	}

	var flowCookieCleared, sessionCookieSet bool
	for _, cookie := range errRec.Result().Cookies() {
		if cookie.Name == o.flowCookieName() && cookie.MaxAge < 0 {
			flowCookieCleared = true
		}
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			sessionCookieSet = true
		}
	}
	if !flowCookieCleared {
		t.Fatal("IdP error did not clear the browser flow cookie")
	}
	if sessionCookieSet {
		t.Fatal("IdP error created an authenticated session")
	}
}

func TestOIDC_HandleCallback_NonceMismatchClearsFlowCookie(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServer(t)
	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{DefaultRole: "user"})
	idp.NextIDToken(map[string]any{
		"sub":                "wrong-nonce-sub",
		"aud":                "test-client",
		"preferred_username": "wrong-nonce",
		"nonce":              "another-browser-flow",
	})

	rec := driveCallback(t, o, "nonce-mismatch", "code")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for nonce mismatch", rec.Code)
	}
	assertOIDCFlowRejected(t, rec, o)
}

func TestOIDC_HandleCallback_AcceptedFlowIsSingleUse(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServer(t)
	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{DefaultRole: "user"})
	idp.NextIDToken(map[string]any{
		"sub":                "single-use-sub",
		"aud":                "test-client",
		"preferred_username": "single-use",
	})
	state, cookie := startOIDCLogin(t, o)

	first := driveCallbackWithCookie(t, o, state, "code", cookie)
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first callback status = %d, want 303 (%s)", first.Code, first.Body.String())
	}
	second := driveCallbackWithCookie(t, o, state, "code", cookie)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback status = %d, want 400 (%s)", second.Code, second.Body.String())
	}
	assertOIDCFlowRejected(t, second, o)
}

func assertOIDCFlowRejected(t *testing.T, rec *httptest.ResponseRecorder, o *OIDC) {
	t.Helper()
	var flowCookieCleared, sessionCookieSet bool
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == o.flowCookieName() && cookie.MaxAge < 0 {
			flowCookieCleared = true
		}
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			sessionCookieSet = true
		}
	}
	if !flowCookieCleared {
		t.Error("rejected callback did not clear the browser flow cookie")
	}
	if sessionCookieSet {
		t.Error("rejected callback created an authenticated session")
	}
}
