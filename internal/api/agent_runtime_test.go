package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

func postRuntime(t *testing.T, srv *Server, agent enrolledAgent, path string, opts ...func(*signOpts)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, nil)
	signPoll(t, req, agent, opts...)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func pollConfig(t *testing.T, srv *Server, agent enrolledAgent) *string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("poll: %d %s", rec.Code, rec.Body.String())
	}
	var updates agentUpdatesResponse
	if err := json.NewDecoder(rec.Body).Decode(&updates); err != nil {
		t.Fatal(err)
	}
	return updates.ConfigYAML
}

func countAudit(t *testing.T, st store.Store, action, resource string) int {
	t.Helper()
	entries, err := st.ListAuditEntries(t.Context(), store.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if e.Action == action && e.Resource == resource {
			n++
		}
	}
	return n
}

func TestAgentRuntime_RecordsAndRedeliversConfig(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	pollConfig(t, srv, agent)
	if cfg := pollConfig(t, srv, agent); cfg != nil {
		t.Fatal("second poll redelivered config before any runtime report")
	}

	rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/linux/1.12.0")
	if rec.Code != http.StatusOK {
		t.Fatalf("report: %d %s", rec.Code, rec.Body.String())
	}
	host, err := st.GetHost(t.Context(), agent.hostID)
	if err != nil {
		t.Fatal(err)
	}
	if host.NebulaVersion != "1.12.0" || host.NebulaOS != "linux" || host.NebulaReportedAt == nil {
		t.Fatalf("host runtime = %q/%q/%v", host.NebulaVersion, host.NebulaOS, host.NebulaReportedAt)
	}
	if cfg := pollConfig(t, srv, agent); cfg == nil {
		t.Fatal("poll after a new runtime report did not redeliver config")
	}

	// The same report again changes nothing and is not audited twice.
	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/linux/1.12.0"); rec.Code != http.StatusOK {
		t.Fatalf("repeat report: %d %s", rec.Code, rec.Body.String())
	}
	if cfg := pollConfig(t, srv, agent); cfg != nil {
		t.Fatal("repeated identical report redelivered config")
	}
	if n := countAudit(t, st, auditHostNebulaRuntimeChanged, agent.hostID); n != 1 {
		t.Errorf("runtime change audit entries = %d, want 1", n)
	}
}

func TestAgentRuntime_NormalizesTaggedVersion(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/darwin/v1.11.2"); rec.Code != http.StatusOK {
		t.Fatalf("report: %d %s", rec.Code, rec.Body.String())
	}
	host, _ := st.GetHost(t.Context(), agent.hostID)
	if host.NebulaVersion != "1.11.2" {
		t.Errorf("stored version = %q, want 1.11.2", host.NebulaVersion)
	}
}

// SEC-REPLAY-001: the runtime report reuses the signed-poll proof, so an
// unsigned, foreign-key, replayed, or path-tampered request must not change
// the host's recorded runtime.
func TestAgentRuntime_SEC_REPLAY_001_RejectsUnauthenticated(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	assertUnchanged := func(step string) {
		t.Helper()
		host, err := st.GetHost(t.Context(), agent.hostID)
		if err != nil {
			t.Fatal(err)
		}
		if host.NebulaVersion != "" && host.NebulaVersion != "1.12.0" {
			t.Fatalf("%s: runtime changed to %q", step, host.NebulaVersion)
		}
	}

	unsigned := httptest.NewRequest(http.MethodPost, "/api/v1/agent/runtime/linux/1.10.3", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, unsigned)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsigned status = %d", rec.Code)
	}
	assertUnchanged("unsigned")

	_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/linux/1.10.3", withPrivateKey(wrongPrivate)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-key status = %d %s", rec.Code, rec.Body.String())
	}
	assertUnchanged("wrong key")

	// A signature covers the exact path: re-pointing a signed report at
	// another version must fail.
	tampered := httptest.NewRequest(http.MethodPost, "/api/v1/agent/runtime/linux/1.12.0", nil)
	signPoll(t, tampered, agent)
	tampered.URL.Path = "/api/v1/agent/runtime/linux/1.10.3"
	tampered.RequestURI = tampered.URL.Path
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, tampered)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered path status = %d %s", rec.Code, rec.Body.String())
	}
	assertUnchanged("tampered path")

	const nonce = "fixed-runtime-nonce"
	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/linux/1.12.0", withNonce(nonce)); rec.Code != http.StatusOK {
		t.Fatalf("valid status = %d %s", rec.Code, rec.Body.String())
	}
	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/linux/1.12.0", withNonce(nonce)); rec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed status = %d %s", rec.Code, rec.Body.String())
	}
}

func TestAgentRuntime_RejectsBlockedHost(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	if _, err := st.BlockHostAndAddToBlocklist(t.Context(), agent.hostID, "test block"); err != nil {
		t.Fatal(err)
	}
	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/linux/1.12.0"); rec.Code != http.StatusForbidden {
		t.Fatalf("blocked status = %d %s", rec.Code, rec.Body.String())
	}
	host, _ := st.GetHost(t.Context(), agent.hostID)
	if host.NebulaVersion != "" {
		t.Errorf("blocked host runtime recorded: %q", host.NebulaVersion)
	}
}

func TestAgentRuntime_RejectsMalformedValues(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	for _, path := range []string{
		"/api/v1/agent/runtime/plan9/1.12.0",
		"/api/v1/agent/runtime/Linux/1.12.0",
		"/api/v1/agent/runtime/linux/1.12",
		"/api/v1/agent/runtime/linux/latest",
		"/api/v1/agent/runtime/linux/1.12.0%20",
	} {
		if rec := postRuntime(t, srv, agent, path); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d %s", path, rec.Code, rec.Body.String())
		}
	}
	host, _ := st.GetHost(t.Context(), agent.hostID)
	if host.NebulaVersion != "" || host.NebulaOS != "" {
		t.Errorf("malformed report recorded %q/%q", host.NebulaVersion, host.NebulaOS)
	}
}

func TestHostAPI_ExposesNebulaRuntimeAndOperatorVersion(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	if rec := postRuntime(t, srv, agent, "/api/v1/agent/runtime/windows/1.11.2"); rec.Code != http.StatusOK {
		t.Fatalf("report: %d %s", rec.Code, rec.Body.String())
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/"+agent.hostID, nil)
	authRequest(get)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, get)
	var host map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&host); err != nil {
		t.Fatal(err)
	}
	if host["nebula_version"] != "1.11.2" || host["nebula_os"] != "windows" || host["nebula_reported_at"] == nil {
		t.Errorf("host JSON runtime = %v/%v/%v", host["nebula_version"], host["nebula_os"], host["nebula_reported_at"])
	}

	patch := func(version string) int {
		raw, _ := json.Marshal(map[string]any{"advanced": map[string]any{"nebula_version": version}})
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+agent.hostID, bytes.NewReader(raw))
		authRequest(req)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := patch("latest"); code != http.StatusBadRequest {
		t.Errorf("invalid advanced.nebula_version: status = %d, want 400", code)
	}
	if code := patch("1.10.3"); code != http.StatusOK {
		t.Fatalf("valid advanced.nebula_version: status = %d", code)
	}
	stored, _ := st.GetHost(t.Context(), agent.hostID)
	if stored.Advanced == nil || stored.Advanced.NebulaVersion != "1.10.3" {
		t.Errorf("advanced = %+v", stored.Advanced)
	}
	if stored.NebulaVersion != "1.11.2" {
		t.Errorf("operator edit overwrote the reported version: %q", stored.NebulaVersion)
	}
}
