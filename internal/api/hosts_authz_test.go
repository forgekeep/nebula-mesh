package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/models"
)

// TestCreateHost_RequiresNetworkOwnership verifies that non-owners cannot create hosts in foreign networks
func TestCreateHost_RequiresNetworkOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators with different CAs
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	// op1 creates a network under ca1
	network := &models.Network{
		ID:    "test-net-1",
		Name:  "Test Network 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), network))

	// op2 tries to create a host in op1's network → should fail with 403
	reqBody := createHostRequest{
		Name:      "attacker-host",
		NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+op2Key)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not be able to create host in foreign network")
}

// TestCreateHost_OwnerSucceeds verifies that owners can create hosts in their
// own networks and that the resulting host inherits the network's CAID rather
// than the server's defaultCAID. The newTestServer fixture's defaultCAID
// belongs to a different operator, so a stamping bug would surface here.
func TestCreateHost_OwnerSucceeds(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create operator with CA
	opKey, _, ca := createOperatorWithCA(t, srv)
	require.NotEqual(t, srv.defaultCAID, ca.ID,
		"fixture invariant: operator CA must differ from defaultCAID")

	// op creates a network under their CA
	network := &models.Network{
		ID:    "test-net-owner",
		Name:  "Owner Network",
		CAID:  ca.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), network))

	// op creates a host in their own network → should succeed
	reqBody := createHostRequest{
		Name:      "owner-host",
		NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+opKey)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code, "owner should be able to create host in own network")

	var resp createHostResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, network.CAID, resp.Host.CAID,
		"host must inherit network.CAID, not server defaultCAID")
}

// TestRotateCert_RequiresOwnership verifies that non-owners cannot trigger
// cert rotation on hosts they don't own. Covers both new_key=true (sets
// pending_rekey) and new_key=false (re-signs immediately). Without an
// ownership gate, this endpoint reproduces the GHSA-598g class of bug on
// the most destructive primitive in the host surface.
func TestRotateCert_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID: "net-rotate-1", Name: "Net Rotate 1",
		CAID: ca1.ID, CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	host1 := &models.Host{
		ID: "host-rotate-1", Name: "Host Rotate 1",
		NetworkID: net1.ID, CAID: ca1.ID, NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// new_key=true (pending_rekey path)
	reqPending := httptest.NewRequest("POST",
		fmt.Sprintf("/api/v1/hosts/%s/rotate-cert?new_key=true", host1.ID), nil)
	reqPending.Header.Set("Authorization", "Bearer "+op2Key)
	wPending := httptest.NewRecorder()
	srv.ServeHTTP(wPending, reqPending)
	assert.Equal(t, http.StatusForbidden, wPending.Code,
		"non-owner should not set pending_rekey on foreign host")

	// new_key=false (immediate re-sign path)
	reqResign := httptest.NewRequest("POST",
		fmt.Sprintf("/api/v1/hosts/%s/rotate-cert?new_key=false", host1.ID), nil)
	reqResign.Header.Set("Authorization", "Bearer "+op2Key)
	wResign := httptest.NewRecorder()
	srv.ServeHTTP(wResign, reqResign)
	assert.Equal(t, http.StatusForbidden, wResign.Code,
		"non-owner should not re-sign foreign host cert")
}

// TestGetHost_RequiresOwnership verifies that non-owners cannot access hosts they don't own
// TestGetHost_OwnerSucceeds verifies that the operator who owns a host's CA
// can read it (happy path).
func TestGetHost_OwnerSucceeds(t *testing.T) {
	srv, testDB := newTestServer(t)

	op1Key, _, ca1 := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-getown-1",
		Name:  "Net GetOwn 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	host1 := &models.Host{
		ID:        "host-getown-1",
		Name:      "Host GetOwn 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/hosts/%s", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op1Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "owner should read their host")
}

func TestGetHost_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	// Create network for op1
	net1 := &models.Network{
		ID:    "net-get-1",
		Name:  "Net Get 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	// Create host for op1
	host1 := &models.Host{
		ID:        "host-get-1",
		Name:      "Host Get 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// op2 tries to GET op1's host → should fail with 403
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/hosts/%s", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not access foreign host")
}

// TestUpdateHost_RequiresOwnership verifies that non-owners cannot modify hosts they don't own
func TestUpdateHost_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	// Create network for op1
	net1 := &models.Network{
		ID:    "net-update-1",
		Name:  "Net Update 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	// Create host for op1
	host1 := &models.Host{
		ID:        "host-update-1",
		Name:      "Host Update 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// op2 tries to PATCH op1's host → should fail with 403
	name := "renamed"
	reqBody := updateHostRequest{Name: &name}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("PATCH", fmt.Sprintf("/api/v1/hosts/%s", host1.ID), bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+op2Key)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not update foreign host")
}

// TestDeleteHost_RequiresOwnership verifies that non-owners cannot delete hosts they don't own
func TestDeleteHost_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	// Create network for op1
	net1 := &models.Network{
		ID:    "net-delete-1",
		Name:  "Net Delete 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	// Create host for op1
	host1 := &models.Host{
		ID:        "host-delete-1",
		Name:      "Host Delete 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// op2 tries to DELETE op1's host → should fail with 403
	req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/hosts/%s", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not delete foreign host")
}

// TestBlockHost_RequiresOwnership verifies that non-owners cannot block hosts they don't own
func TestBlockHost_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	// Create network for op1
	net1 := &models.Network{
		ID:    "net-block-1",
		Name:  "Net Block 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	// Create host for op1
	host1 := &models.Host{
		ID:        "host-block-1",
		Name:      "Host Block 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// op2 tries to BLOCK op1's host → should fail with 403
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/hosts/%s/block", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not block foreign host")
}

// TestUnblockHost_RequiresOwnership verifies that non-owners cannot unblock hosts they don't own
func TestUnblockHost_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	// Create network for op1
	net1 := &models.Network{
		ID:    "net-unblock-1",
		Name:  "Net Unblock 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	// Create host for op1
	host1 := &models.Host{
		ID:        "host-unblock-1",
		Name:      "Host Unblock 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		Status:    models.HostStatusBlocked,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// op2 tries to UNBLOCK op1's host → should fail with 403
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/hosts/%s/unblock", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not unblock foreign host")
}

// TestReenroll_OwnershipAuthz verifies that non-owners cannot reenroll hosts they don't own
// This reproduces the vulnerability from the advisory
func TestReenroll_OwnershipAuthz(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	// Create network for op1
	net1 := &models.Network{
		ID:    "net-reenroll-1",
		Name:  "Net Reenroll 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	// Create host for op1
	host1 := &models.Host{
		ID:        "host-reenroll-1",
		Name:      "Host Reenroll 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// op2 tries to REENROLL op1's host → should fail with 403
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/hosts/%s/reenroll", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not reenroll foreign host (advisory reproducer)")
}

// TestRegenerateEnrollmentToken_OwnershipAuthz verifies that non-owners cannot regenerate tokens for hosts they don't own
func TestRegenerateEnrollmentToken_OwnershipAuthz(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two operators
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	// Create network for op1
	net1 := &models.Network{
		ID:    "net-regen-1",
		Name:  "Net Regen 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	// Create host for op1
	host1 := &models.Host{
		ID:        "host-regen-1",
		Name:      "Host Regen 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// op2 tries to REGENERATE enrollment token for op1's host → should fail with 403
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/hosts/%s/enrollment-token", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not regenerate token for foreign host")
}

// TestListHosts_ScopedToOwnedCAs verifies that non-admin operators see only hosts under their own CAs
// This demonstrates the information-disclosure fix: non-owners must not see foreign hosts in list
func TestListHosts_ScopedToOwnedCAs(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Create two non-admin operators with different CAs
	opAKey, _, caA := createOperatorWithCA(t, srv)
	opBKey, _, caB := createOperatorWithCA(t, srv)

	// Create network for operator A
	netA := &models.Network{
		ID:    "net-list-a",
		Name:  "Network A",
		CAID:  caA.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), netA))

	// Create network for operator B
	netB := &models.Network{
		ID:    "net-list-b",
		Name:  "Network B",
		CAID:  caB.ID,
		CIDRs: []string{"10.1.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), netB))

	// Create host under CA A
	hostA := &models.Host{
		ID:        "host-list-a",
		Name:      "Host A",
		NetworkID: netA.ID,
		CAID:      caA.ID,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), hostA))

	// Create host under CA B
	hostB := &models.Host{
		ID:        "host-list-b",
		Name:      "Host B",
		NetworkID: netB.ID,
		CAID:      caB.ID,
		NebulaIPs: []string{"10.1.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), hostB))

	// Operator A lists hosts with their token
	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+opAKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "list hosts should succeed")

	// Parse response
	var hosts []*models.Host
	err := json.NewDecoder(w.Body).Decode(&hosts)
	require.NoError(t, err, "should parse JSON response")

	// Verify operator A sees only hostA
	hostIDs := make([]string, len(hosts))
	for i, h := range hosts {
		hostIDs[i] = h.ID
	}

	assert.Contains(t, hostIDs, hostA.ID, "operator A should see their own host")
	assert.NotContains(t, hostIDs, hostB.ID, "operator A should not see operator B's host")

	// Operator B lists hosts with their token
	req = httptest.NewRequest("GET", "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+opBKey)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "list hosts should succeed")

	// Parse response
	hosts = []*models.Host{}
	err = json.NewDecoder(w.Body).Decode(&hosts)
	require.NoError(t, err, "should parse JSON response")

	// Verify operator B sees only hostB
	hostIDs = make([]string, len(hosts))
	for i, h := range hosts {
		hostIDs[i] = h.ID
	}

	assert.Contains(t, hostIDs, hostB.ID, "operator B should see their own host")
	assert.NotContains(t, hostIDs, hostA.ID, "operator B should not see operator A's host")
}
