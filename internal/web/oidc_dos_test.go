package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/forgekeep/nebula-mesh/internal/ratelimit"
)

// fillStatesToCap plants `n` non-expired states by direct mutation, bypassing
// the cap check so tests can drive rememberState/HandleLogin against a full map.
func fillStatesToCap(o *OIDC, n int) {
	future := time.Now().Add(oidcStateTTL)
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	for i := 0; i < n; i++ {
		o.states["seed-"+strconv.Itoa(i)] = future
	}
}

// TestOIDC_RememberState_RefusesAtCap is the GHSA-m3cx-mwpg-32jg unit guard:
// once the live-state map reaches the ceiling, rememberState must refuse new
// entries instead of growing without bound. Entries are non-expired, so the
// lazy sweep cannot reclaim them.
func TestOIDC_RememberState_RefusesAtCap(t *testing.T) {
	o := newOIDCForStateTests(t)
	fillStatesToCap(o, oidcMaxLiveStates)

	if ok := o.rememberState("one-too-many"); ok {
		t.Fatal("rememberState admitted a state past the cap")
	}
	if got := o.stateCount(); got != oidcMaxLiveStates {
		t.Fatalf("state count = %d, want %d (map grew past cap)", got, oidcMaxLiveStates)
	}
	if o.hasState("one-too-many") {
		t.Error("refused state must not be stored")
	}

	// Below the cap, admission resumes.
	o.stateMu.Lock()
	delete(o.states, "seed-0")
	o.stateMu.Unlock()
	if ok := o.rememberState("now-fits"); !ok {
		t.Fatal("rememberState should admit once below the cap")
	}
}

// TestOIDC_HandleLogin_RefusesAtCap verifies the handler fails closed with a
// 503 + Retry-After when the pending-state ceiling is reached, rather than
// allocating another entry.
func TestOIDC_HandleLogin_RefusesAtCap(t *testing.T) {
	o := newOIDCForStateTests(t)
	o.oauth = &oauth2.Config{
		ClientID:    "cid",
		RedirectURL: "https://nebula-mesh.test/ui/oidc/callback",
		Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize"},
	}
	fillStatesToCap(o, oidcMaxLiveStates)

	req := httptest.NewRequest(http.MethodGet, "/ui/oidc/login", nil)
	rec := httptest.NewRecorder()
	o.HandleLogin(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on cap refusal")
	}
	if got := o.stateCount(); got != oidcMaxLiveStates {
		t.Errorf("state count = %d, want %d (refused login still allocated)", got, oidcMaxLiveStates)
	}
}

// TestOIDC_LoginRoute_RateLimited confirms /ui/oidc/login now shares the auth
// rate-limit bucket, so an unauthenticated client cannot flood the allocation
// path. Before the fix the route was registered outside any limiter.
func TestOIDC_LoginRoute_RateLimited(t *testing.T) {
	w := newRateLimitWeb(t)
	w.WithRateLimiter(ratelimit.New(ratelimit.Config{
		Enabled: true,
		Groups:  map[string]ratelimit.GroupConfig{"auth": {Rate: 0.001, Burst: 2}},
	}))
	o := &OIDC{
		states: map[string]time.Time{},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		oauth: &oauth2.Config{
			ClientID:    "cid",
			RedirectURL: "https://nebula-mesh.test/ui/oidc/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize"},
		},
	}
	w.WithOIDC(o)

	const ip = "10.2.2.2:9999"
	// Burst (2) admitted.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ui/oidc/login", nil)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d should be admitted within burst, got 429", i)
		}
	}
	// 3rd refused by the limiter.
	req := httptest.NewRequest(http.MethodGet, "/ui/oidc/login", nil)
	req.RemoteAddr = ip
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("3rd GET /ui/oidc/login: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
}
