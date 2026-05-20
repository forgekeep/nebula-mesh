package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetFirewall_RequiresOwnership verifies that a non-owner cannot read
// firewall rules of another operator's network.
func TestGetFirewall_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-fw-get-1",
		Name:  "Net FW Get 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/networks/%s/firewall", net1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not read firewall rules of foreign network")
}

// TestUpdateFirewall_RequiresOwnership verifies that a non-owner cannot
// mutate firewall rules of another operator's network.
func TestUpdateFirewall_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-fw-upd-1",
		Name:  "Net FW Upd 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	body, _ := json.Marshal(map[string]any{
		"inbound": []map[string]string{
			{"port": "22", "proto": "tcp", "group": "admin"},
		},
		"outbound": []map[string]string{
			{"port": "any", "proto": "any", "group": "any"},
		},
	})
	req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/networks/%s/firewall", net1.ID), bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not update firewall rules of foreign network")
}

// TestGetFirewall_OwnerSucceeds verifies the happy path: the owner of the
// network's CA can read firewall rules.
func TestGetFirewall_OwnerSucceeds(t *testing.T) {
	srv, testDB := newTestServer(t)

	op1Key, _, ca1 := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-fw-get-owner",
		Name:  "Net FW Get Owner",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/networks/%s/firewall", net1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op1Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "owner should read firewall rules of their network")
}

// TestUpdateFirewall_OwnerSucceeds verifies the happy path for mutation.
func TestUpdateFirewall_OwnerSucceeds(t *testing.T) {
	srv, testDB := newTestServer(t)

	op1Key, _, ca1 := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-fw-upd-owner",
		Name:  "Net FW Upd Owner",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	body, _ := json.Marshal(map[string]any{
		"inbound": []map[string]string{
			{"port": "22", "proto": "tcp", "group": "admin"},
		},
		"outbound": []map[string]string{
			{"port": "any", "proto": "any", "group": "any"},
		},
	})
	req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/networks/%s/firewall", net1.ID), bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+op1Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "owner should update firewall rules of their network")
}
