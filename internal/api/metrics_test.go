package api

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestMetricsEndpoint_PrometheusFormat asserts that /metrics now serves
// Prometheus exposition format (text/plain; version=0.0.4) and that every
// metric required by issue #40 is registered.
func TestMetricsEndpoint_PrometheusFormat(t *testing.T) {
	srv, _ := newTestServer(t)

	// Warm-up: hit a handler so the HTTP counters/histograms record at
	// least one sample. Prometheus's text exposition only emits metrics
	// that have data — pre-seeding zeros for {method, route, status}
	// would explode cardinality, so we exercise one route instead.
	wReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	wRec := httptest.NewRecorder()
	srv.ServeHTTP(wRec, wReq)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain (prometheus exposition)", ct)
	}

	body := w.Body.String()
	required := []string{
		"nebula_mgmt_http_requests_total",
		"nebula_mgmt_http_request_duration_seconds",
		"nebula_mgmt_enrollments_total",
		"nebula_mgmt_cert_renewals_total",
		"nebula_mgmt_audit_entries_total",
		"nebula_mgmt_operator_logins_total",
		"nebula_mgmt_ca_signatures_total",
		"nebula_mgmt_hosts",
		"nebula_mgmt_certificates_expiring_seconds",
	}
	for _, want := range required {
		if !strings.Contains(body, want) {
			t.Errorf("metric %q not registered in /metrics output", want)
		}
	}
}

// TestMetricsEndpoint_RecordsHTTPRequests asserts that requests hitting the
// router increment the HTTP requests counter for the matched chi route.
func TestMetricsEndpoint_RecordsHTTPRequests(t *testing.T) {
	srv, _ := newTestServer(t)

	// Fire a handful of requests we expect to be observed.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, `nebula_mgmt_http_requests_total{`) {
		t.Fatalf("http_requests_total has no samples after traffic:\n%s", body)
	}
	if !strings.Contains(body, `route="/healthz"`) {
		t.Errorf("expected route=\"/healthz\" label, got:\n%s", body)
	}
}

// TestMetricsEndpoint_EnrollmentIncrementsCounter is the end-to-end probe
// required by issue #40: a successful enrollment must move
// nebula_mgmt_enrollments_total{result="ok"}.
func TestMetricsEndpoint_EnrollmentIncrementsCounter(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	// 1. Create host record.
	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "metrics-host", NebulaIPs: []string{"192.168.100.10"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create host: status = %d, body = %s", w.Code, w.Body.String())
	}
	var created createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode created host: %v", err)
	}

	// 2. Generate a real public key + enroll.
	privKey := make([]byte, 32)
	if _, err := rand.Read(privKey); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub)

	_, _, signingPEM := generateSigningKeypair(t)
	enrollBody, _ := json.Marshal(enrollRequest{
		Token:         created.EnrollmentToken,
		PublicKeyPEM:  string(pubPEM),
		SigningPubPEM: signingPEM,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewBuffer(enrollBody))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: status = %d, body = %s", w.Code, w.Body.String())
	}

	// 3. Scrape /metrics and assert that nebula_mgmt_enrollments_total{result="ok"}
	//    is at least 1.
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metrics: status = %d", w.Code)
	}
	body2, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body2), `nebula_mgmt_enrollments_total{result="ok"} 1`) {
		t.Errorf("enrollments_total{result=\"ok\"} was not incremented; metrics body:\n%s", string(body2))
	}
}

// TestMetricsEndpoint_HostsGauge ensures the hosts gauge reflects the current
// store state grouped by status (and is exported at all).
func TestMetricsEndpoint_HostsGauge(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)

	// Seed two hosts in different statuses so the gauge has at least two
	// labelsets to scrape.
	for _, s := range []models.HostStatus{models.HostStatusPending, models.HostStatusEnrolled, models.HostStatusImporting} {
		h := &models.Host{
			ID: "h_" + string(s), NetworkID: netID, Name: "h-" + string(s),
			NebulaIPs: []string{"192.168.100." + string(s[0:1]) + "0"},
			Groups:    []string{}, Role: models.HostRoleHost, Status: s,
		}
		if err := st.CreateHost(req(t).Context(), h); err != nil {
			t.Fatalf("seed host %s: %v", s, err)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	body := w.Body.String()
	if !strings.Contains(body, `nebula_mgmt_hosts{`) {
		t.Errorf("hosts gauge missing in /metrics:\n%s", body)
	}
	if !strings.Contains(body, `status="importing"`) {
		t.Errorf("importing host gauge missing in /metrics:\n%s", body)
	}
}

// TestExpvarEndpoint_LegacyPath retains backward compat with operators that
// still scrape Go's expvar handler — it moves to /debug/vars when the
// Prometheus exporter takes /metrics.
func TestExpvarEndpoint_LegacyPath(t *testing.T) {
	srv, _ := newTestServer(t)
	r := httptest.NewRequest(http.MethodGet, "/debug/vars", nil)
	authRequest(r) // /debug/vars is bearer-gated since #187
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/debug/vars: status = %d, want 200", w.Code)
	}
	// expvar serves JSON
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// req returns a fresh *http.Request used just for its context (test helper).
func req(t *testing.T) *http.Request {
	t.Helper()
	return httptest.NewRequest(http.MethodGet, "/", nil)
}

// newTestServerWithMetrics is like newTestServer but lets the caller decide
// whether the Prometheus exporter is wired into /metrics. Used by the opt-out
// test below; production code goes through cli/serve.go.
func newTestServerWithMetrics(t *testing.T, enabled bool) (*Server, interface{}) {
	t.Helper()
	srv, st := newTestServer(t)
	srv.WithMetricsEnabled(enabled)
	return srv, st
}

// TestMetricsEndpoint_DisabledByOption verifies the air-gapped opt-out path:
// when a server is built with metrics turned off, /metrics returns 404 and
// /debug/vars is still served (operators that disable Prometheus can fall
// back to expvar without losing observability entirely).
func TestMetricsEndpoint_DisabledByOption(t *testing.T) {
	srv, _ := newTestServerWithMetrics(t, false)

	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("disabled /metrics: status = %d, want 404", w.Code)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/debug/vars", nil)
	authRequest(r2) // /debug/vars is bearer-gated since #187
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, r2)
	if w2.Code != http.StatusOK {
		t.Errorf("/debug/vars: status = %d, want 200", w2.Code)
	}
}
