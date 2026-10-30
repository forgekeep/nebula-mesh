package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The config a host polls follows the Nebula release its agent reports: a
// 1.12-only override stays out until the host reports 1.12.
func TestAgentConfig_RendersGatedOverrideAfterRuntimeReport(t *testing.T) {
	srv, _ := newTestServer(t)
	agent := enrolledFixture(t, srv)

	raw, _ := json.Marshal(map[string]any{"advanced": map[string]any{"udp_offloads": true}})
	patch := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+agent.hostID, bytes.NewReader(raw))
	authRequest(patch)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, patch)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rec.Code, rec.Body.String())
	}

	cfg := pollConfig(t, srv, agent)
	if cfg == nil {
		t.Fatal("poll after the edit returned no config")
	}
	if strings.Contains(*cfg, "udp_offloads") {
		t.Fatalf("unknown-version host got a 1.12-only key:\n%s", *cfg)
	}

	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/linux/1.12.0"); rec.Code != http.StatusOK {
		t.Fatalf("report: %d %s", rec.Code, rec.Body.String())
	}
	cfg = pollConfig(t, srv, agent)
	if cfg == nil || !strings.Contains(*cfg, "udp_offloads: true") {
		t.Fatalf("1.12 linux host did not get udp_offloads after its report:\n%v", cfg)
	}
}

func TestUpdateHost_RejectsOverrideTheReportedRuntimeCannotUse(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/windows/1.12.0"); rec.Code != http.StatusOK {
		t.Fatalf("report: %d", rec.Code)
	}
	patch := func(adv map[string]any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]any{"advanced": adv})
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+agent.hostID, bytes.NewReader(raw))
		authRequest(req)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	rec := patch(map[string]any{"udp_offloads": true})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "requires linux; host reports windows") {
		t.Fatalf("offloads on windows: %d %s", rec.Code, rec.Body.String())
	}
	host, _ := st.GetHost(t.Context(), agent.hostID)
	if host.Advanced != nil && host.Advanced.UDPOffloads != nil {
		t.Fatal("rejected override was stored")
	}
	if rec := patch(map[string]any{"local_api_control_enabled": false}); rec.Code != http.StatusOK {
		t.Fatalf("local API on windows 1.12: %d %s", rec.Code, rec.Body.String())
	}
}
