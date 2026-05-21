package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juev/nebula-mesh/internal/config"
)

// TestOIDC_HandleCallback_ErrorParamConsumesState pins that the IdP-error
// early-return branch invalidates the state cookie. Without this, an
// attacker who can induce the IdP to redirect back with ?error=... on the
// first callback hit could replay the same state on a second hit that
// carries a valid code.
func TestOIDC_HandleCallback_ErrorParamConsumesState(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServer(t)
	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{
		AllowedEmails: []string{"alice@example.com"},
		DefaultRole:   "user",
	})

	const stateValue = "state-replay-defense"

	// First: drive a callback with ?error=access_denied. This used to
	// early-return without consuming the state.
	errRec := driveCallbackWithError(t, o, stateValue, "access_denied")
	if errRec.Code != http.StatusBadRequest {
		t.Errorf("error-path status = %d, want 400 (body: %s)", errRec.Code, errRec.Body.String())
	}

	// State must no longer be in the in-memory map. consumeState would
	// also return false on a second call.
	if o.hasState(stateValue) {
		t.Fatal("state was not consumed on the IdP-error path: replay window still open")
	}

	// Second: drive a follow-up callback with the same state value and a
	// legitimate-looking code. The state cookie should already be
	// invalidated — expect 400 "invalid oidc state", not a successful
	// session.
	idp.NextIDToken(map[string]any{
		"sub":                "alice-sub",
		"aud":                "test-client",
		"email":              "alice@example.com",
		"email_verified":     true,
		"preferred_username": "alice",
		"name":               "Alice",
	})
	// driveCallback re-seats the state — bypass that for the replay test
	// so we observe the post-error state.
	req := httptest.NewRequest("GET", "/ui/oidc/callback?state="+stateValue+"&code=code-replay", nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookieName, Value: stateValue})
	replayRec := httptest.NewRecorder()
	o.HandleCallback(replayRec, req)

	if replayRec.Code != http.StatusBadRequest {
		t.Errorf("replay status = %d, want 400 (body: %s)", replayRec.Code, replayRec.Body.String())
	}
	if !strings.Contains(replayRec.Body.String(), "invalid oidc state") {
		t.Errorf("replay body = %q, want 'invalid oidc state'", replayRec.Body.String())
	}
}
