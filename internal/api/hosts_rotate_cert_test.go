package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRotateCert_SameKey(t *testing.T) {
	// Sleep one second so the re-signed cert's NotBefore differs from the
	// fixture's enrollment cert — Nebula certs use second-precision
	// timestamps, and signing the same public key in the same wall-clock
	// second produces an identical fingerprint, which collides on the
	// global UNIQUE(certificates.fingerprint) constraint.
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	time.Sleep(time.Second)

	host, err := st.GetHostByFingerprint(context.Background(), agent.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	beforeFP := host.CertFingerprint

	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+host.ID+"/rotate-cert?new_key=false", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp rotateCertResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.NewKey {
		t.Errorf("NewKey = true, want false")
	}
	if resp.CertificatePEM == "" {
		t.Errorf("CertificatePEM empty")
	}

	got, err := st.GetHost(context.Background(), host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.CertFingerprint == beforeFP {
		t.Errorf("CertFingerprint unchanged (%q) — expected re-sign to mint new fp", got.CertFingerprint)
	}
}

func TestRotateCert_NewKey_SetsPending(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	host, _ := st.GetHostByFingerprint(context.Background(), agent.fingerprint)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+host.ID+"/rotate-cert?new_key=true", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202, body = %s", w.Code, w.Body.String())
	}

	got, _ := st.GetHost(context.Background(), host.ID)
	if !got.PendingRekey {
		t.Errorf("PendingRekey = false, want true")
	}
}

func TestRotateCert_NewKey_ConflictOnSecond(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	host, _ := st.GetHostByFingerprint(context.Background(), agent.fingerprint)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+host.ID+"/rotate-cert?new_key=true", nil)
		authRequest(req)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if i == 0 && w.Code != http.StatusAccepted {
			t.Fatalf("first call: %d, want 202", w.Code)
		}
		if i == 1 && w.Code != http.StatusConflict {
			t.Fatalf("second call: %d, want 409", w.Code)
		}
	}
}

func TestRotateCert_HostNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/missing/rotate-cert", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRotateCert_RequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/anything/rotate-cert", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestPoll_EmitsRekeyToken_WhenPending(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	host, _ := st.GetHostByFingerprint(context.Background(), agent.fingerprint)
	if err := st.SetPendingRekey(context.Background(), host.ID); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
	var resp agentUpdatesResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if !resp.RekeyRequired {
		t.Error("RekeyRequired = false, want true")
	}
	if resp.EnrollmentToken == "" {
		t.Error("EnrollmentToken empty")
	}

	// Pending flag must be cleared so a follow-up poll does not mint a
	// second token.
	got, _ := st.GetHost(context.Background(), host.ID)
	if got.PendingRekey {
		t.Errorf("PendingRekey still true after rekey token was minted")
	}
}
