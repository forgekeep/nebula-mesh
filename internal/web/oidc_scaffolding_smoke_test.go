package web

import (
	"net/http"
	"testing"

	"github.com/juev/nebula-mesh/internal/config"
)

// TestOIDC_MockIDP_HappyPath is the scaffolding smoke test: it drives the
// full callback flow end-to-end through the mock IdP and asserts that a
// session cookie lands. It deliberately omits the email claim so the
// allowlist gate, the email_verified gate, and any future email-shaped
// checks don't affect the scaffolding's own coverage.
func TestOIDC_MockIDP_HappyPath(t *testing.T) {
	_, s := newTestWeb(t)
	idp := setupOIDCServer(t)
	o := newOIDCFromMock(t, idp, s, config.OIDCConfig{
		DefaultRole: "user",
	})

	idp.NextIDToken(map[string]any{
		"sub":                "scaffold-sub",
		"aud":                "test-client",
		"preferred_username": "scaffold-user",
		"name":               "Scaffold User",
	})

	rec := driveCallback(t, o, "state-scaffold", "code-scaffold")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (body: %s)", rec.Code, rec.Body.String())
	}

	// Session cookie must be set as a side effect of the successful flow.
	var sessionSet bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			sessionSet = true
			break
		}
	}
	if !sessionSet {
		t.Error("expected session cookie after successful OIDC callback")
	}

	// Replay must reuse a non-empty state token: hasState reflects the
	// in-memory map, and consumeState should have just dropped this one.
	if o.hasState("state-scaffold") {
		t.Error("state was not consumed after successful callback")
	}
}
