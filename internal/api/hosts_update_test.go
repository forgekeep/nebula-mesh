package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

func TestUpdateHost_RouteRegistered(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	// Create a test host.
	hostBody, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "test-host",
		NebulaIPs: []string{"192.168.100.1"},
		Groups:    []string{"test"},
		Role:      "host",
	})
	hostReq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(hostBody))
	authRequest(hostReq)
	hostRec := httptest.NewRecorder()
	srv.ServeHTTP(hostRec, hostReq)

	if hostRec.Code != http.StatusCreated {
		t.Fatalf("failed to create host: %d %s", hostRec.Code, hostRec.Body.String())
	}

	var hostResp createHostResponse
	if err := json.NewDecoder(hostRec.Body).Decode(&hostResp); err != nil {
		t.Fatalf("decode host response: %v", err)
	}

	hostID := hostResp.Host.ID

	// PATCH /api/v1/hosts/{id} with a simple name change.
	reqBody, _ := json.Marshal(map[string]interface{}{
		"name": "updated-name",
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+hostID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	// Route should be registered (not 405 Method Not Allowed).
	if rec.Code == http.StatusMethodNotAllowed {
		t.Fatalf("PATCH route not registered; got %d %s", rec.Code, http.StatusText(rec.Code))
	}
	// Implementation returns 200 (no-op, same name)
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotImplemented {
		t.Fatalf("unexpected status; got %d %s", rec.Code, http.StatusText(rec.Code))
	}
}

// Helper to create a host with specific values
func createHostHelper(t *testing.T, srv *Server, netID string, name, nebulaIP string, adv *models.HostAdvanced) *models.Host {
	hostBody, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      name,
		NebulaIPs: []string{nebulaIP},
		Groups:    []string{},
		Role:      "host",
		Advanced:  adv,
	})
	hostReq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(hostBody))
	authRequest(hostReq)
	hostRec := httptest.NewRecorder()
	srv.ServeHTTP(hostRec, hostReq)

	if hostRec.Code != http.StatusCreated {
		t.Fatalf("failed to create host: %d %s", hostRec.Code, hostRec.Body.String())
	}

	var hostResp createHostResponse
	if err := json.NewDecoder(hostRec.Body).Decode(&hostResp); err != nil {
		t.Fatalf("decode host response: %v", err)
	}

	return hostResp.Host
}

// TestUpdateHost_HappyPath_Advanced tests PATCH with MTU change
func TestUpdateHost_HappyPath_Advanced(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	// Create a host with MTU=1300
	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", &models.HostAdvanced{
		MTU: 1300,
	})

	// PATCH to change MTU to 1280
	reqBody, _ := json.Marshal(updateHostRequest{
		Advanced: &models.HostAdvanced{
			MTU: 1280,
		},
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "expected 200, got %d: %s", rec.Code, rec.Body.String())

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.Equal(t, 1280, updatedHost.Advanced.MTU, "MTU should be updated to 1280")

	// Check audit entry
	entries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: "host.update",
		Limit:  10,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(entries), "expected 1 audit entry")

	// Verify audit details is valid JSON with advanced.mtu
	var details map[string]map[string]any
	require.NoError(t, json.Unmarshal([]byte(entries[0].Details), &details))
	require.Contains(t, details, "advanced.mtu")
}

// TestUpdateHost_HappyPath_Rename tests PATCH to change host name
func TestUpdateHost_HappyPath_Rename(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// PATCH to rename
	newName := "web-2"
	reqBody, _ := json.Marshal(updateHostRequest{
		Name: &newName,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "expected 200, got %d: %s", rec.Code, rec.Body.String())

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.Equal(t, "web-2", updatedHost.Name)
	require.True(t, updatedHost.PendingRekey, "rename should set PendingRekey")

	// Check audit entry
	entries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: "host.update",
		Limit:  10,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
	var details map[string]map[string]any
	require.NoError(t, json.Unmarshal([]byte(entries[0].Details), &details))
	require.Contains(t, details, "name")
}

// TestUpdateHost_NoChanges tests that no-op PATCH skips audit
func TestUpdateHost_NoChanges_NoAudit_NoRepublish(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Get initial updated_at timestamp
	freshHost, err := srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	initialUpdatedAt := freshHost.UpdatedAt

	// PATCH with same values (no changes)
	reqBody, _ := json.Marshal(updateHostRequest{
		Name: &host.Name,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Check that no audit entry was created
	entries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: "host.update",
		Limit:  10,
	})
	require.NoError(t, err)
	require.Equal(t, 0, len(entries), "no-op should not create audit entry")

	// Check that updated_at was not changed
	freshHost2, err := srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.Equal(t, initialUpdatedAt, freshHost2.UpdatedAt)
}

// TestUpdateHost_SameIPNotDuplicate tests PATCH with same IP doesn't trigger duplicate error
func TestUpdateHost_SameIPNotDuplicate(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// PATCH with same IP
	sameIPList := []string{host.NebulaIPs[0]}
	reqBody, _ := json.Marshal(updateHostRequest{
		NebulaIPs: &sameIPList,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "same IP should not be rejected as duplicate: %s", rec.Body.String())
}

// TestUpdateHost_DuplicateIPRejected tests PATCH with duplicate IP in network
func TestUpdateHost_DuplicateIPRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host1 := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)
	host2 := createHostHelper(t, srv, netID, "web-2", "192.168.100.2", nil)

	// Try to change host2's IP to host1's IP
	dupIPList := []string{host1.NebulaIPs[0]}
	reqBody, _ := json.Marshal(updateHostRequest{
		NebulaIPs: &dupIPList,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host2.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code, "duplicate IP should be rejected")
}

// TestUpdateHost_NebulaIPOutsideCIDR tests PATCH with IP outside network CIDR
func TestUpdateHost_NebulaIPOutsideCIDR(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Try to change to IP outside network CIDR (192.169.* instead of 192.168.*)
	outsideIPList := []string{"192.169.100.1"}
	reqBody, _ := json.Marshal(updateHostRequest{
		NebulaIPs: &outsideIPList,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestUpdateHost_EmptyName tests PATCH with empty name
func TestUpdateHost_EmptyName(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Try to set empty name
	emptyName := ""
	reqBody, _ := json.Marshal(updateHostRequest{
		Name: &emptyName,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestUpdateHost_InvalidMTU tests PATCH with invalid MTU value
func TestUpdateHost_InvalidMTU(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Try to set MTU to invalid value (too high)
	reqBody, _ := json.Marshal(updateHostRequest{
		Advanced: &models.HostAdvanced{
			MTU: 99999,
		},
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestUpdateHost_InvalidRole tests PATCH with invalid role
func TestUpdateHost_InvalidRole(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Try to set invalid role
	invalidRole := "foobar"
	reqBody, _ := json.Marshal(updateHostRequest{
		Role: &invalidRole,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestUpdateHost_LighthouseWithoutPublicIP tests PATCH setting lighthouse role without public_ip
func TestUpdateHost_LighthouseWithoutPublicIP(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Try to set role=lighthouse without public_ip
	lighthouseRole := "lighthouse"
	reqBody, _ := json.Marshal(updateHostRequest{
		Role: &lighthouseRole,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestUpdateHost_HostNotFound tests PATCH to non-existent host
func TestUpdateHost_HostNotFound(t *testing.T) {
	srv, _ := newTestServer(t)

	reqBody, _ := json.Marshal(updateHostRequest{
		Name: stringPtr("newname"),
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/non-existent-id", bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNotFound, rec.Code)
}

// TestUpdateHost_NetworkIDIgnored tests that network_id field is ignored (not in request struct)
func TestUpdateHost_NetworkIDIgnored(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Try to send network_id in the body (should be ignored)
	reqBody := []byte(`{"network_id":"other-network","name":"web-2"}`)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.Equal(t, netID, updatedHost.NetworkID, "network_id should not change")
}

// Helper to create a string pointer
func stringPtr(s string) *string {
	return &s
}

// TestUpdateHost_RepublishHostConfig verifies that host config version is reset to 0 on any update
func TestUpdateHost_RepublishHostConfig(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", &models.HostAdvanced{
		MTU: 1300,
	})

	// Manually bump host config version to simulate already-published state
	err := srv.store.UpdateHostConfigVersion(context.Background(), host.ID, 5)
	require.NoError(t, err)

	version, err := srv.store.GetHostConfigVersion(context.Background(), host.ID)
	require.NoError(t, err)
	require.Equal(t, 5, version, "setup: host config version should be 5")

	// PATCH to change MTU
	reqBody, _ := json.Marshal(updateHostRequest{
		Advanced: &models.HostAdvanced{
			MTU: 1280,
		},
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Verify host config version was reset to 0
	version, err = srv.store.GetHostConfigVersion(context.Background(), host.ID)
	require.NoError(t, err)
	require.Equal(t, 0, version, "host config version should be reset to 0")

	// Verify network config version is unchanged
	netVersion, err := srv.store.GetNetworkConfigVersion(context.Background(), netID)
	require.NoError(t, err)
	require.NotEqual(t, 0, netVersion, "network config version should not be 0 (unchanged)")
}

// TestUpdateHost_RoleFlipToLighthouse_BumpsNetwork verifies that role flip bumps network config version
func TestUpdateHost_RoleFlipToLighthouse_BumpsNetwork(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Get initial network config version
	initialNetVersion, err := srv.store.GetNetworkConfigVersion(context.Background(), netID)
	require.NoError(t, err)

	// PATCH to change role to lighthouse
	lighthouseRole := "lighthouse"
	publicIP := "203.0.113.1"
	listenPort := 4242
	reqBody, _ := json.Marshal(updateHostRequest{
		Role:       &lighthouseRole,
		PublicIP:   &publicIP,
		ListenPort: &listenPort,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.True(t, updatedHost.IsLighthouse, "host should be lighthouse")

	// Verify network config version was bumped
	newNetVersion, err := srv.store.GetNetworkConfigVersion(context.Background(), netID)
	require.NoError(t, err)
	require.Greater(t, newNetVersion, initialNetVersion, "network config version should be bumped on role flip")
}

// TestUpdateHost_RoleFlipFromLighthouse_BumpsNetwork verifies that removing lighthouse role bumps network
func TestUpdateHost_RoleFlipFromLighthouse_BumpsNetwork(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	// Create a lighthouse host
	publicIP := "203.0.113.1"
	listenPort := 4242
	hostBody, _ := json.Marshal(createHostRequest{
		NetworkID:  netID,
		Name:       "lighthouse-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{},
		Role:       "lighthouse",
		PublicIP:   publicIP,
		ListenPort: listenPort,
	})
	hostReq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(hostBody))
	authRequest(hostReq)
	hostRec := httptest.NewRecorder()
	srv.ServeHTTP(hostRec, hostReq)
	require.Equal(t, http.StatusCreated, hostRec.Code)

	var hostResp createHostResponse
	require.NoError(t, json.NewDecoder(hostRec.Body).Decode(&hostResp))
	host := hostResp.Host

	// Get initial network config version
	initialNetVersion, err := srv.store.GetNetworkConfigVersion(context.Background(), netID)
	require.NoError(t, err)

	// PATCH to change role back to host
	hostRole := "host"
	reqBody, _ := json.Marshal(updateHostRequest{
		Role: &hostRole,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.False(t, updatedHost.IsLighthouse, "host should no longer be lighthouse")

	// Verify network config version was bumped
	newNetVersion, err := srv.store.GetNetworkConfigVersion(context.Background(), netID)
	require.NoError(t, err)
	require.Greater(t, newNetVersion, initialNetVersion, "network config version should be bumped on role flip away from lighthouse")
}

// TestUpdateHost_NoRepublishNetworkOnAdvancedChange verifies network version unchanged for non-role changes
func TestUpdateHost_NoRepublishNetworkOnAdvancedChange(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Get initial network config version
	initialNetVersion, err := srv.store.GetNetworkConfigVersion(context.Background(), netID)
	require.NoError(t, err)

	// PATCH to change advanced.mtu only (not role)
	reqBody, _ := json.Marshal(updateHostRequest{
		Advanced: &models.HostAdvanced{
			MTU: 1280,
		},
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Verify network config version is unchanged
	newNetVersion, err := srv.store.GetNetworkConfigVersion(context.Background(), netID)
	require.NoError(t, err)
	require.Equal(t, initialNetVersion, newNetVersion, "network config version should not change for non-role updates")
}

// TestUpdateHost_RenameSetsPendingRekey verifies that renaming a host sets PendingRekey
func TestUpdateHost_RenameSetsPendingRekey(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Verify PendingRekey is initially false
	freshHost, err := srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.False(t, freshHost.PendingRekey, "setup: PendingRekey should initially be false")

	// PATCH to rename
	newName := "web-2"
	reqBody, _ := json.Marshal(updateHostRequest{
		Name: &newName,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Verify PendingRekey is set in response
	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.True(t, updatedHost.PendingRekey, "rename should set PendingRekey in response")

	// Verify PendingRekey is persisted
	freshHost, err = srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.True(t, freshHost.PendingRekey, "rename should set PendingRekey in database")
}

// TestUpdateHost_ChangeIPSetsPendingRekey verifies that changing NebulaIP sets PendingRekey
func TestUpdateHost_ChangeIPSetsPendingRekey(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Verify PendingRekey is initially false
	freshHost, err := srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.False(t, freshHost.PendingRekey, "setup: PendingRekey should initially be false")

	// PATCH to change NebulaIP
	newIPList := []string{"192.168.100.99"}
	reqBody, _ := json.Marshal(updateHostRequest{
		NebulaIPs: &newIPList,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Verify PendingRekey is set in response
	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.True(t, updatedHost.PendingRekey, "IP change should set PendingRekey in response")

	// Verify PendingRekey is persisted
	freshHost, err = srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.True(t, freshHost.PendingRekey, "IP change should set PendingRekey in database")
}

// TestUpdateHost_AdvancedOnlyNoPendingRekey verifies that Advanced-only changes don't set PendingRekey
func TestUpdateHost_AdvancedOnlyNoPendingRekey(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Verify PendingRekey is initially false
	freshHost, err := srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.False(t, freshHost.PendingRekey, "setup: PendingRekey should initially be false")

	// PATCH to change advanced.mtu only
	reqBody, _ := json.Marshal(updateHostRequest{
		Advanced: &models.HostAdvanced{
			MTU: 1280,
		},
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	// Verify PendingRekey is NOT set
	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.False(t, updatedHost.PendingRekey, "Advanced-only change should not set PendingRekey")

	// Verify PendingRekey is still false in database
	freshHost, err = srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.False(t, freshHost.PendingRekey, "Advanced-only change should not set PendingRekey in database")
}

// TestUpdateHost_IdempotentRekey verifies that SetPendingRekey is idempotent
func TestUpdateHost_IdempotentRekey(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	// Manually set PendingRekey to true
	err := srv.store.SetPendingRekey(context.Background(), host.ID)
	require.NoError(t, err)

	freshHost, err := srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.True(t, freshHost.PendingRekey, "setup: PendingRekey should be true")

	// PATCH to rename (which would also trigger SetPendingRekey)
	newName := "web-2"
	reqBody, _ := json.Marshal(updateHostRequest{
		Name: &newName,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	// Should return 200, not 409 or 500 (idempotent)
	require.Equal(t, http.StatusOK, rec.Code, "PATCH should return 200 even when PendingRekey is already set")

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.True(t, updatedHost.PendingRekey, "PendingRekey should still be true")

	// Verify audit entry was created
	entries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: "host.update",
		Limit:  10,
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(entries), "audit entry should be created")

	// Verify audit diff contains name
	var details map[string]map[string]any
	require.NoError(t, json.Unmarshal([]byte(entries[0].Details), &details))
	require.Contains(t, details, "name", "audit should contain name diff")
}

// TestUpdateHost_HappyPath_RoleFlip verifies role flip with all required fields
func TestUpdateHost_HappyPath_RoleFlip(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)
	require.False(t, host.IsLighthouse, "setup: host should not be lighthouse")

	// PATCH to change role to lighthouse with required fields
	lighthouseRole := "lighthouse"
	publicIP := "203.0.113.1"
	listenPort := 4242
	reqBody, _ := json.Marshal(updateHostRequest{
		Role:       &lighthouseRole,
		PublicIP:   &publicIP,
		ListenPort: &listenPort,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.Equal(t, "lighthouse", string(updatedHost.Role))
	require.True(t, updatedHost.IsLighthouse, "host should be lighthouse")
	require.False(t, updatedHost.IsRelay, "host should not be relay")
	require.Equal(t, publicIP, updatedHost.PublicIP)
	require.Equal(t, listenPort, updatedHost.ListenPort)
}

// TestUpdateHost_HappyPath_ChangeIP verifies changing NebulaIP to a valid new IP
func TestUpdateHost_HappyPath_ChangeIP(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)
	require.Equal(t, "192.168.100.1", host.NebulaIPs[0], "setup: initial IP")

	// PATCH to change NebulaIP
	newIPList := []string{"192.168.100.50"}
	reqBody, _ := json.Marshal(updateHostRequest{
		NebulaIPs: &newIPList,
	})

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updatedHost))
	require.Len(t, updatedHost.NebulaIPs, 1)
	require.Equal(t, newIPList[0], updatedHost.NebulaIPs[0])
	require.True(t, updatedHost.PendingRekey, "IP change should set PendingRekey")
}

// TestCreateHost_AcceptsNebulaIPs tests POST with multiple addresses
func TestCreateHost_AcceptsNebulaIPs(t *testing.T) {
	srv, _ := newTestServer(t)

	// Create a dual-stack network
	body, _ := json.Marshal(map[string]interface{}{
		"name":  "dual-net",
		"cidrs": []string{"10.0.0.0/24", "fd00::/64"},
	})
	netReq := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	authRequest(netReq)
	netRec := httptest.NewRecorder()
	srv.ServeHTTP(netRec, netReq)

	var net models.Network
	require.NoError(t, json.NewDecoder(netRec.Body).Decode(&net))

	// Create host with multiple addresses
	hostBody, _ := json.Marshal(map[string]interface{}{
		"network_id": net.ID,
		"name":       "dual-addr-host",
		"nebula_ips": []string{"10.0.0.5", "fd00::5"},
		"role":       "host",
	})
	hostReq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(hostBody))
	authRequest(hostReq)
	hostRec := httptest.NewRecorder()
	srv.ServeHTTP(hostRec, hostReq)

	require.Equal(t, http.StatusCreated, hostRec.Code, "body: %s", hostRec.Body.String())

	var hostResp createHostResponse
	require.NoError(t, json.NewDecoder(hostRec.Body).Decode(&hostResp))

	require.Len(t, hostResp.Host.NebulaIPs, 2)
	require.Equal(t, "10.0.0.5", hostResp.Host.NebulaIPs[0])
	require.Equal(t, "fd00::5", hostResp.Host.NebulaIPs[1])
}

// TestCreateHost_RejectsSingularNebulaIP tests that old singular field is rejected
func TestCreateHost_RejectsSingularNebulaIP(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	// Try to create with old singular field
	body := `{"network_id":"` + netID + `","name":"bad-host","nebula_ip":"192.168.100.5","role":"host"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBufferString(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, "should reject singular nebula_ip field")

	var errResp map[string]string
	require.NoError(t, json.NewDecoder(w.Body).Decode(&errResp))

	errMsg := errResp["error"]
	require.NotEmpty(t, errMsg, "error message should not be empty")
	require.Contains(t, errMsg, "nebula_ip", "error should mention old field")
	require.Contains(t, errMsg, "nebula_ips", "error should suggest new field")
}

// TestUpdateHost_NebulaIPs_ReplacesList tests that PATCH with nebula_ips replaces list
func TestUpdateHost_NebulaIPs_ReplacesList(t *testing.T) {
	srv, _ := newTestServer(t)

	// Create dual-stack network
	netBody, _ := json.Marshal(map[string]interface{}{
		"name":  "dual-net",
		"cidrs": []string{"10.0.0.0/24", "fd00::/64"},
	})
	netReq := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(netBody))
	authRequest(netReq)
	netRec := httptest.NewRecorder()
	srv.ServeHTTP(netRec, netReq)

	var net models.Network
	require.NoError(t, json.NewDecoder(netRec.Body).Decode(&net))

	// Create host with 2 addresses
	hostBody, _ := json.Marshal(map[string]interface{}{
		"network_id": net.ID,
		"name":       "test-host",
		"nebula_ips": []string{"10.0.0.5", "fd00::5"},
		"role":       "host",
	})
	hostReq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(hostBody))
	authRequest(hostReq)
	hostRec := httptest.NewRecorder()
	srv.ServeHTTP(hostRec, hostReq)

	var hostResp createHostResponse
	require.NoError(t, json.NewDecoder(hostRec.Body).Decode(&hostResp))
	hostID := hostResp.Host.ID

	// PATCH to replace addresses
	newIPs := []string{"10.0.0.6"}
	patchBody, _ := json.Marshal(map[string]interface{}{
		"nebula_ips": newIPs,
	})
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+hostID, bytes.NewBuffer(patchBody))
	authRequest(patchReq)
	patchRec := httptest.NewRecorder()
	srv.ServeHTTP(patchRec, patchReq)

	require.Equal(t, http.StatusOK, patchRec.Code, "body: %s", patchRec.Body.String())

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(patchRec.Body).Decode(&updatedHost))

	require.Len(t, updatedHost.NebulaIPs, 1)
	require.Equal(t, "10.0.0.6", updatedHost.NebulaIPs[0])
	require.True(t, updatedHost.PendingRekey, "address change should set PendingRekey")
}

// TestUpdateHost_OmittedNebulaIPs_Untouched tests that PATCH without nebula_ips leaves them unchanged
func TestUpdateHost_OmittedNebulaIPs_Untouched(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "test-host", "192.168.100.5", nil)
	originalIPs := host.NebulaIPs

	// PATCH with groups only (no nebula_ips field, no name change)
	newGroups := []string{"new-group"}
	patchBody, _ := json.Marshal(map[string]interface{}{
		"groups": newGroups,
	})
	patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(patchBody))
	authRequest(patchReq)
	patchRec := httptest.NewRecorder()
	srv.ServeHTTP(patchRec, patchReq)

	require.Equal(t, http.StatusOK, patchRec.Code)

	var updatedHost models.Host
	require.NoError(t, json.NewDecoder(patchRec.Body).Decode(&updatedHost))

	require.Equal(t, originalIPs, updatedHost.NebulaIPs, "addresses should be unchanged")
	require.False(t, updatedHost.PendingRekey, "groups-only change should not set PendingRekey")
}
