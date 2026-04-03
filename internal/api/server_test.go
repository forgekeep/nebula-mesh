package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juev/nebula-mgmt/internal/models"
	"github.com/juev/nebula-mgmt/internal/pki"
	"github.com/juev/nebula-mgmt/internal/store"
)

const testAPIKey = "test-api-key-12345"

func newTestServer(t *testing.T) (*Server, *store.SQLiteStore) {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	ca, _, err := pki.NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.Default()
	srv := NewServer(s, ca, testAPIKey, logger, CAConfig{})
	return srv, s
}

func authRequest(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
}

// --- Health ---

func TestHealth(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want ok", resp["status"])
	}
}

// --- Auth Middleware ---

func TestAuthMiddleware_NoHeader(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_InvalidKey(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_ValidKey(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- Networks ---

func TestCreateAndListNetworks(t *testing.T) {
	srv, _ := newTestServer(t)

	body := `{"name":"test-net","cidr":"192.168.100.0/24"}`
	req := httptest.NewRequest("POST", "/api/v1/networks", bytes.NewBufferString(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var created models.Network
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if created.Name != "test-net" {
		t.Errorf("name = %q, want test-net", created.Name)
	}

	// List
	req = httptest.NewRequest("GET", "/api/v1/networks", nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", w.Code, http.StatusOK)
	}

	var networks []models.Network
	if err := json.NewDecoder(w.Body).Decode(&networks); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(networks) != 1 {
		t.Errorf("len = %d, want 1", len(networks))
	}
}

// --- Hosts ---

func createNetwork(t *testing.T, srv *Server) string {
	t.Helper()
	body := `{"name":"test-net","cidr":"192.168.100.0/24"}`
	req := httptest.NewRequest("POST", "/api/v1/networks", bytes.NewBufferString(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var net models.Network
	if err := json.NewDecoder(w.Body).Decode(&net); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return net.ID
}

func TestCreateHost_InvalidRole(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "bad-role-host",
		NebulaIP:  "192.168.100.10",
		Role:      "invalid",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid role, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestCreateAndGetHost(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "web-1",
		NebulaIP:  "192.168.100.10",
		Groups:    []string{"web"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Host.Name != "web-1" {
		t.Errorf("name = %q, want web-1", resp.Host.Name)
	}
	if resp.EnrollmentToken == "" {
		t.Error("enrollment token is empty")
	}

	// Get host
	req = httptest.NewRequest("GET", "/api/v1/hosts/"+resp.Host.ID, nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("get status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestDeleteHost(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "to-delete", NebulaIP: "192.168.100.20",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	req = httptest.NewRequest("DELETE", "/api/v1/hosts/"+resp.Host.ID, nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// Verify deleted
	req = httptest.NewRequest("GET", "/api/v1/hosts/"+resp.Host.ID, nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("get after delete status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestDeleteHost_WithCertBlocklisted(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "enrolled-host", NebulaIP: "192.168.100.30",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Simulate enrolled host with cert fingerprint
	host := resp.Host
	host.CertFingerprint = "fp-to-block"
	host.Status = "enrolled"
	if err := st.UpdateHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}

	// Delete should add to blocklist
	req = httptest.NewRequest("DELETE", "/api/v1/hosts/"+host.ID, nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// Verify cert is in blocklist
	bl, err := st.GetBlocklist(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, fp := range bl {
		if fp == "fp-to-block" {
			found = true
			break
		}
	}
	if !found {
		t.Error("cert fingerprint not found in blocklist after delete")
	}
}

func TestCreateNetwork_InvalidCIDR(t *testing.T) {
	srv, _ := newTestServer(t)

	body := `{"name":"bad-net","cidr":"invalid/33"}`
	req := httptest.NewRequest("POST", "/api/v1/networks", bytes.NewBufferString(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestCreateHost_InvalidIP(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "bad-host", NebulaIP: "not-an-ip",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestCreateHost_InvalidPort(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	for _, port := range []int{-1, 70000, 65536} {
		body, _ := json.Marshal(createHostRequest{
			NetworkID:  netID,
			Name:       "bad-port",
			NebulaIP:   "192.168.100.10",
			ListenPort: port,
		})
		req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
		authRequest(req)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("port=%d: status = %d, want %d", port, w.Code, http.StatusBadRequest)
		}
	}
}

func TestCreateHost_ValidPort(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	for _, port := range []int{0, 4242, 65535} {
		body, _ := json.Marshal(createHostRequest{
			NetworkID:  netID,
			Name:       fmt.Sprintf("host-port-%d", port),
			NebulaIP:   fmt.Sprintf("192.168.100.%d", 10+port%200),
			ListenPort: port,
		})
		req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
		authRequest(req)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("port=%d: status = %d, want %d, body: %s", port, w.Code, http.StatusCreated, w.Body.String())
		}
	}
}

func TestCreateHost_EmptyGroup(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	for _, groups := range [][]string{
		{""},
		{"  "},
		{"web", ""},
	} {
		body, _ := json.Marshal(createHostRequest{
			NetworkID: netID,
			Name:      "bad-groups",
			NebulaIP:  "192.168.100.10",
			Groups:    groups,
		})
		req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
		authRequest(req)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("groups=%v: status = %d, want %d", groups, w.Code, http.StatusBadRequest)
		}
	}
}

func TestCreateHost_ValidGroups(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "good-groups",
		NebulaIP:  "192.168.100.10",
		Groups:    []string{"web", "prod"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
}

func TestFirewallRules_DefaultAndCRUD(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	// GET returns defaults
	req := httptest.NewRequest("GET", "/api/v1/networks/"+netID+"/firewall", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d, body: %s", w.Code, w.Body.String())
	}

	var rules firewallRulesRequest
	if err := json.NewDecoder(w.Body).Decode(&rules); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(rules.Inbound) != 1 || rules.Inbound[0].Proto != "icmp" {
		t.Errorf("expected default inbound icmp rule, got %+v", rules.Inbound)
	}

	// PUT custom rules
	customRules := `{"inbound":[{"port":"443","proto":"tcp","group":"web"}],"outbound":[{"port":"any","proto":"any","group":"any"}]}`
	req = httptest.NewRequest("PUT", "/api/v1/networks/"+netID+"/firewall", bytes.NewBufferString(customRules))
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("put status = %d, body: %s", w.Code, w.Body.String())
	}

	// GET returns stored rules
	req = httptest.NewRequest("GET", "/api/v1/networks/"+netID+"/firewall", nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if err := json.NewDecoder(w.Body).Decode(&rules); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(rules.Inbound) != 1 || rules.Inbound[0].Port != "443" {
		t.Errorf("expected stored inbound rule port=443, got %+v", rules.Inbound)
	}
}

func TestFirewallRules_ValidationEmptyProto(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	invalidRules := `{"inbound":[{"port":"443","proto":"","group":"web"}],"outbound":[]}`
	req := httptest.NewRequest("PUT", "/api/v1/networks/"+netID+"/firewall", bytes.NewBufferString(invalidRules))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty proto, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestFirewallRules_ValidationEmptyPort(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	invalidRules := `{"inbound":[],"outbound":[{"port":"","proto":"tcp","group":"any"}]}`
	req := httptest.NewRequest("PUT", "/api/v1/networks/"+netID+"/firewall", bytes.NewBufferString(invalidRules))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty port, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestFirewallRules_CorruptedJSON(t *testing.T) {
	srv, s := newTestServer(t)
	netID := createNetwork(t, srv)

	// Write corrupted JSON directly into DB
	if err := s.SetNetworkConfig(context.Background(), netID, "firewall", `{invalid json}`); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/v1/networks/"+netID+"/firewall", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for corrupted firewall JSON, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestRotateCA_Persists(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	ca, _, err := pki.NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := dir + "/ca.crt"
	keyPath := dir + "/ca.key"
	passphrase := "test-pass"

	// Save initial CA
	if err := ca.Save(certPath, keyPath, passphrase); err != nil {
		t.Fatal(err)
	}

	srv := NewServer(s, ca, testAPIKey, slog.Default(), CAConfig{
		CertPath:   certPath,
		KeyPath:    keyPath,
		Passphrase: passphrase,
	})

	// Get old fingerprint
	oldFP, _ := ca.CACertFingerprint()

	// Rotate
	req := httptest.NewRequest("POST", "/api/v1/ca/rotate", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, body: %s", w.Code, w.Body.String())
	}

	// Load CA from disk and verify it's different
	loaded, err := pki.LoadCA(certPath, keyPath, passphrase)
	if err != nil {
		t.Fatalf("load rotated CA: %v", err)
	}
	newFP, _ := loaded.CACertFingerprint()
	if newFP == oldFP {
		t.Error("CA fingerprint should change after rotation")
	}
}

func TestConcurrentCAAccess(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	ca, _, err := pki.NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	srv := NewServer(s, ca, testAPIKey, slog.Default(), CAConfig{
		CertPath:   dir + "/ca.crt",
		KeyPath:    dir + "/ca.key",
		Passphrase: "test",
	})
	if err := ca.Save(dir+"/ca.crt", dir+"/ca.key", "test"); err != nil {
		t.Fatal(err)
	}

	// Run concurrent GET /ca and POST /ca/rotate — must not race
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			req := httptest.NewRequest("GET", "/api/v1/ca", nil)
			authRequest(req)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
		}()
	}
	go func() {
		defer func() { done <- struct{}{} }()
		req := httptest.NewRequest("POST", "/api/v1/ca/rotate", nil)
		authRequest(req)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
	}()

	for i := 0; i < 11; i++ {
		<-done
	}
}

func TestGetAuditLog_LimitBounds(t *testing.T) {
	srv, _ := newTestServer(t)

	// limit > 1000 → should be capped to 1000 (still OK)
	req := httptest.NewRequest("GET", "/api/v1/audit-log?limit=5000", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	// limit = "abc" → bad request
	req = httptest.NewRequest("GET", "/api/v1/audit-log?limit=abc", nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d for invalid limit, want %d", w.Code, http.StatusBadRequest)
	}

	// limit = -5 → bad request
	req = httptest.NewRequest("GET", "/api/v1/audit-log?limit=-5", nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d for negative limit, want %d", w.Code, http.StatusBadRequest)
	}

	// no limit → uses explicit default, returns OK
	req = httptest.NewRequest("GET", "/api/v1/audit-log", nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d for no limit, want %d", w.Code, http.StatusOK)
	}
}

func TestWriteJSON_EncodeError(t *testing.T) {
	w := httptest.NewRecorder()
	// channels are not JSON-serializable — Encode returns an error
	writeJSON(w, http.StatusOK, make(chan int))

	// Should not panic; status code is still written
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestMaxBytesReader(t *testing.T) {
	srv, _ := newTestServer(t)

	// Create a valid JSON body larger than 1MB
	// Use a long string field to exceed the limit
	bigStr := string(bytes.Repeat([]byte("x"), 1<<20+1))
	body, _ := json.Marshal(map[string]string{"name": bigStr, "cidr": "10.0.0.0/24"})

	req := httptest.NewRequest("POST", "/api/v1/networks", bytes.NewReader(body))
	authRequest(req)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	// With MaxBytesReader, reading >1MB body should fail
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for oversized body", w.Code, http.StatusBadRequest)
	}
}

func TestEnroll_HostDeletedAfterTokenCreated(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)

	// Create host and get enrollment token
	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "doomed", NebulaIP: "192.168.100.50",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create host: status = %d, body: %s", w.Code, w.Body.String())
	}
	var resp createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	// Delete host bypassing FK cascade (simulates race condition:
	// concurrent delete between ConsumeToken and GetHost)
	if _, err := st.DB().Exec("PRAGMA foreign_keys=OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec("DELETE FROM hosts WHERE id = ?", resp.Host.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec("PRAGMA foreign_keys=ON"); err != nil {
		t.Fatal(err)
	}

	// Try enrollment — token is consumed OK, but GetHost returns ErrNotFound
	enrollBody, _ := json.Marshal(enrollRequest{
		Token:        resp.EnrollmentToken,
		PublicKeyPEM: "dummy-key",
	})
	req = httptest.NewRequest("POST", "/api/v1/enroll", bytes.NewBuffer(enrollBody))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}

	// Should have specific error message, not generic "enrollment failed"
	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatal(err)
	}
	if errResp["error"] != "host not found" {
		t.Errorf("error = %q, want %q", errResp["error"], "host not found")
	}
}

func TestHostNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/hosts/nonexistent", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}
