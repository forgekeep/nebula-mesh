package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// TestPoll_AutoRenewsInsideWindow drives the signed-poll handler with the
// server clock advanced into the host cert's renewal window and asserts the
// response carries a freshly-signed cert whose NotBefore tracks the injected
// clock — a handler-level companion to the simtest CERT_RENEWAL invariant.
func TestPoll_AutoRenewsInsideWindow(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	ci, err := st.GetCertificateInfo(context.Background(), agent.hostID)
	if err != nil {
		t.Fatalf("get cert info: %v", err)
	}
	// 1 day before expiry on a 30-day cert ⇒ ~3% TTL remaining, inside the 20% window.
	clk := ci.NotAfter.Add(-24 * time.Hour).Truncate(time.Second)
	srv.WithClock(func() time.Time { return clk })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent, withTimestamp(clk.UTC().Format(time.RFC3339)))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("poll status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp agentUpdatesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.CertificatePEM == nil {
		t.Fatal("expected a renewed certificate in the poll response, got none")
	}
	renewed, _, err := cert.UnmarshalCertificateFromPEM([]byte(*resp.CertificatePEM))
	if err != nil {
		t.Fatalf("parse renewed cert: %v", err)
	}
	if renewed.NotBefore().Unix() != clk.Unix() {
		t.Errorf("renewed NotBefore = %s, want injected clock %s", renewed.NotBefore(), clk)
	}
}

// TestPoll_NoRenewOutsideWindow verifies a poll well before the renewal window
// returns no new certificate.
func TestPoll_NoRenewOutsideWindow(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	ci, err := st.GetCertificateInfo(context.Background(), agent.hostID)
	if err != nil {
		t.Fatalf("get cert info: %v", err)
	}
	// 1 day after issuance on a 30-day cert ⇒ ~96% TTL remaining, outside the window.
	clk := ci.NotBefore.Add(24 * time.Hour).Truncate(time.Second)
	srv.WithClock(func() time.Time { return clk })

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent, withTimestamp(clk.UTC().Format(time.RFC3339)))
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("poll status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp agentUpdatesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.CertificatePEM != nil {
		t.Error("did not expect a renewed certificate outside the renewal window")
	}
}
