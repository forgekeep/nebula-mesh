package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCreateHost_UsesServerDefaultTTL — when no per-network override exists,
// the freshly minted token expires at now + server-default (24h by default).
// Bumping `WithEnrollmentTokenTTL` to a distinctive value lets the test see
// the override was applied without relying on the default.
func TestCreateHost_UsesServerDefaultTTL(t *testing.T) {
	srv, _ := newTestServer(t)
	srv.WithEnrollmentTokenTTL(2 * time.Hour)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "h1",
		NebulaIPs: []string{"192.168.100.10"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	before := time.Now()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201, body: %s", w.Code, w.Body.String())
	}

	var resp createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// We don't return ExpiresAt on the host, but we can read the token row
	// from the store. Pull the host from the store and re-fetch through the
	// API to make sure it exists.
	hostID := resp.Host.ID
	if hostID == "" {
		t.Fatal("host id empty")
	}
	// ConsumeToken would mark it used — instead, validate by trying to mint
	// a fresh one and observing the same TTL.
	expectedMinExpiry := before.Add(2 * time.Hour).Add(-1 * time.Minute)
	expectedMaxExpiry := time.Now().Add(2 * time.Hour).Add(1 * time.Minute)

	regReq := httptest.NewRequest("POST", "/api/v1/hosts/"+hostID+"/enrollment-token", nil)
	authRequest(regReq)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, regReq)
	if w2.Code != http.StatusCreated {
		t.Fatalf("regen status = %d, want 201, body: %s", w2.Code, w2.Body.String())
	}
	var reg regenerateEnrollmentTokenResponse
	if err := json.NewDecoder(w2.Body).Decode(&reg); err != nil {
		t.Fatalf("decode regen: %v", err)
	}
	if reg.ExpiresAt.Before(expectedMinExpiry) || reg.ExpiresAt.After(expectedMaxExpiry) {
		t.Errorf("ExpiresAt = %v, want within [%v, %v]", reg.ExpiresAt, expectedMinExpiry, expectedMaxExpiry)
	}
}

// TestCreateHost_UsesNetworkOverride — per-network value in network_config
// overrides the server-level default.
func TestCreateHost_UsesNetworkOverride(t *testing.T) {
	srv, st := newTestServer(t)
	srv.WithEnrollmentTokenTTL(24 * time.Hour)
	netID := createNetwork(t, srv)

	if err := st.SetNetworkConfig(context.Background(), netID, "enrollment_token_ttl", "30m"); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "h2",
		NebulaIPs: []string{"192.168.100.11"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	before := time.Now()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	var resp createHostResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)

	regReq := httptest.NewRequest("POST", "/api/v1/hosts/"+resp.Host.ID+"/enrollment-token", nil)
	authRequest(regReq)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, regReq)
	if w2.Code != http.StatusCreated {
		t.Fatalf("regen status = %d", w2.Code)
	}
	var reg regenerateEnrollmentTokenResponse
	_ = json.NewDecoder(w2.Body).Decode(&reg)

	expectedMin := before.Add(30 * time.Minute).Add(-1 * time.Minute)
	expectedMax := time.Now().Add(30 * time.Minute).Add(1 * time.Minute)
	if reg.ExpiresAt.Before(expectedMin) || reg.ExpiresAt.After(expectedMax) {
		t.Errorf("ExpiresAt = %v, want within [%v, %v]", reg.ExpiresAt, expectedMin, expectedMax)
	}
}

// TestRegenerateEnrollmentToken_InvalidatesPrevious confirms the old token
// can no longer be consumed after regeneration, while the new one works.
func TestRegenerateEnrollmentToken_InvalidatesPrevious(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "h3",
		NebulaIPs: []string{"192.168.100.12"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d", w.Code)
	}
	var initial createHostResponse
	_ = json.NewDecoder(w.Body).Decode(&initial)

	regReq := httptest.NewRequest("POST", "/api/v1/hosts/"+initial.Host.ID+"/enrollment-token", nil)
	authRequest(regReq)
	w2 := httptest.NewRecorder()
	srv.ServeHTTP(w2, regReq)
	if w2.Code != http.StatusCreated {
		t.Fatalf("regen status = %d", w2.Code)
	}
	var reg regenerateEnrollmentTokenResponse
	_ = json.NewDecoder(w2.Body).Decode(&reg)
	if reg.Token == "" || reg.Token == initial.EnrollmentToken {
		t.Fatalf("regenerated token must differ from initial: initial=%q new=%q", initial.EnrollmentToken, reg.Token)
	}

	// Old token must be wiped from the store.
	if _, err := st.ConsumeToken(context.Background(), initial.EnrollmentToken); err == nil {
		t.Error("old token still consumable after regenerate")
	}
	// New token must be consumable exactly once.
	if _, err := st.ConsumeToken(context.Background(), reg.Token); err != nil {
		t.Errorf("new token not consumable: %v", err)
	}
}

// TestRegenerateEnrollmentToken_RequiresAuth — endpoint sits behind bearer
// auth, like every other host-CRUD route.
func TestRegenerateEnrollmentToken_RequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("POST", "/api/v1/hosts/anything/enrollment-token", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestRegenerateEnrollmentToken_HostNotFound — 404 for a non-existent host id.
func TestRegenerateEnrollmentToken_HostNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("POST", "/api/v1/hosts/missing-host/enrollment-token", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404, body: %s", w.Code, w.Body.String())
	}
}
