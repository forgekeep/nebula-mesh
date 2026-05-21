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

// TestCreateNetwork_RequiresAdmin verifies that handleCreateNetwork is
// admin-only: non-admin operators cannot create networks (createNetworkRequest
// has no CAID field, so non-admin creation would produce orphan networks).
func TestCreateNetwork_RequiresAdmin(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")

	body, _ := json.Marshal(map[string]any{
		"name":  "n",
		"cidrs": []string{"10.0.0.0/8"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+userKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-admin should not create networks")
}

// TestGetNetwork_RequiresOwnership verifies that a non-owner gets 403 when
// trying to read another operator's network.
func TestGetNetwork_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-get-1",
		Name:  "Net Get 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/networks/%s", net1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not read foreign network")
}

// TestGetNetwork_OwnerSucceeds verifies the happy path: the operator who owns
// the network's CA can read it.
func TestGetNetwork_OwnerSucceeds(t *testing.T) {
	srv, testDB := newTestServer(t)

	op1Key, _, ca1 := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-get-owner-1",
		Name:  "Net Get Owner 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/networks/%s", net1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op1Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "owner should read their network")
}

// TestCreateNetwork_AdminSucceeds verifies the admin happy path for network
// creation.
func TestCreateNetwork_AdminSucceeds(t *testing.T) {
	srv, _ := newTestServer(t)
	adminKey := createUserWithAPIKey(t, srv, "admin")

	body, _ := json.Marshal(map[string]any{
		"name":  "admin-created-net",
		"cidrs": []string{"10.99.0.0/16"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code, "admin should create networks; body=%s", w.Body.String())
}

// TestListNetworks_ScopedToOwnedCAs verifies that a non-admin operator only
// sees networks under their own CAs.
func TestListNetworks_ScopedToOwnedCAs(t *testing.T) {
	srv, testDB := newTestServer(t)

	keyA, _, caA := createOperatorWithCA(t, srv)
	_, _, caB := createOperatorWithCA(t, srv)

	netA := &models.Network{
		ID:    "net-A",
		Name:  "Net A",
		CAID:  caA.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	netB := &models.Network{
		ID:    "net-B",
		Name:  "Net B",
		CAID:  caB.ID,
		CIDRs: []string{"10.1.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), netA))
	require.NoError(t, testDB.CreateNetwork(context.Background(), netB))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer "+keyA)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var got []*models.Network
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))

	var ids []string
	for _, n := range got {
		ids = append(ids, n.ID)
	}
	assert.Contains(t, ids, "net-A", "owner should see their own network")
	assert.NotContains(t, ids, "net-B", "non-admin should not see foreign network")
}
