package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// #187: /debug/vars and (optionally) /metrics must be gated; /readyz must not
// leak internal error detail.

func TestReadyz_DoesNotLeakInternalError(t *testing.T) {
	srv, st := newTestServer(t)
	st.Close() // force store.Ping to fail

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, leaked := body["error"]; leaked {
		t.Errorf("/readyz leaked internal error detail: %q", body["error"])
	}
	if body["status"] != "unavailable" {
		t.Errorf("status field = %q, want unavailable", body["status"])
	}
}

func TestDebugVars_RequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t)

	noAuth := httptest.NewRequest(http.MethodGet, "/debug/vars", nil)
	wn := httptest.NewRecorder()
	srv.ServeHTTP(wn, noAuth)
	if wn.Code != http.StatusUnauthorized {
		t.Fatalf("/debug/vars without auth: status = %d, want 401", wn.Code)
	}

	authed := httptest.NewRequest(http.MethodGet, "/debug/vars", nil)
	authRequest(authed)
	wa := httptest.NewRecorder()
	srv.ServeHTTP(wa, authed)
	if wa.Code != http.StatusOK {
		t.Fatalf("/debug/vars with auth: status = %d, want 200", wa.Code)
	}
}

func TestMetrics_PublicByDefault(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/metrics default (no auth): status = %d, want 200", w.Code)
	}
}

func TestMetrics_RequireAuth_Gates(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.WithMetricsRequireAuth(true)

	noAuth := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	wn := httptest.NewRecorder()
	srv.ServeHTTP(wn, noAuth)
	if wn.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics with require_auth, no token: status = %d, want 401", wn.Code)
	}

	authed := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	authRequest(authed)
	wa := httptest.NewRecorder()
	srv.ServeHTTP(wa, authed)
	if wa.Code != http.StatusOK {
		t.Fatalf("/metrics with require_auth, valid token: status = %d, want 200", wa.Code)
	}
}
