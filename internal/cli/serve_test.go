package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBuildMux_RoutesPerIssue69 verifies the acceptance criteria from #69:
//
//   - GET /                → UI handler
//   - GET /ui/...          → UI handler
//   - GET /static/...      → UI handler
//   - GET /favicon.ico     → UI handler
//   - GET /api/v1/enroll   → API handler
//   - GET /healthz         → API handler
//   - GET /readyz          → API handler
//   - GET /metrics         → API handler
//   - GET /debug/vars      → API handler
//   - GET /health          → API handler (legacy alias)
//   - GET /api/unknown     → API handler (lets it 404, not UI)
func TestBuildMux_RoutesPerIssue69(t *testing.T) {
	apiSrv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "api")
		w.WriteHeader(http.StatusOK)
	})
	uiSrv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "ui")
		w.WriteHeader(http.StatusOK)
	})

	mux := buildMux(uiSrv, apiSrv)

	cases := []struct {
		path    string
		handler string
	}{
		{"/", "ui"},
		{"/ui/", "ui"},
		{"/ui/hosts", "ui"},
		{"/static/app.css", "ui"},
		{"/favicon.ico", "ui"},
		{"/api/", "api"},
		{"/api/v1/enroll", "api"},
		{"/api/v1/agent/updates", "api"},
		{"/api/unknown-endpoint", "api"},
		{"/healthz", "api"},
		{"/readyz", "api"},
		{"/metrics", "api"},
		{"/debug/vars", "api"},
		{"/debug/pprof/", "api"},
		{"/health", "api"},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			mux.ServeHTTP(rr, req)
			if got := rr.Header().Get("X-Handler"); got != tc.handler {
				t.Errorf("path %s routed to %q, want %q", tc.path, got, tc.handler)
			}
		})
	}
}

func TestBuildMux_UnknownApiPathDoesNotFallThroughToUI(t *testing.T) {
	// API stub mimics chi's NotFound behavior: returns 404 with a distinctive body.
	apiSrv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("api-not-found"))
	})
	uiSrv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If the UI ever sees /api/... we've regressed.
		t.Fatalf("UI should not handle %s", r.URL.Path)
	})
	mux := buildMux(uiSrv, apiSrv)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/does-not-exist", nil)
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "api-not-found") {
		t.Errorf("body = %q, want API-generated 404", rr.Body.String())
	}
}
