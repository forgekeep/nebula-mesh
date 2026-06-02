package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// putFirewall is a small helper that PUTs the given rule body as the network
// owner and returns the response recorder.
func putFirewall(t *testing.T, srv http.Handler, ownerKey, netID string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/v1/networks/%s/firewall", netID), bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+ownerKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// TestUpdateFirewall_RejectsEmptyGroup verifies that a rule without a target
// group selector is rejected: an empty group is marshaled into the network
// config and pushed to every agent, where Nebula treats it as match-any — a
// broader allow than intended (#195).
func TestUpdateFirewall_RejectsEmptyGroup(t *testing.T) {
	srv, testDB := newTestServer(t)

	op1Key, _, ca1 := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-fw-empty-group",
		Name:  "Net FW Empty Group",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	body, _ := json.Marshal(map[string]any{
		"inbound": []map[string]string{
			{"port": "22", "proto": "tcp", "group": ""},
		},
		"outbound": []map[string]string{
			{"port": "any", "proto": "any", "group": "any"},
		},
	})
	w := putFirewall(t, srv, op1Key, net1.ID, body)

	assert.Equal(t, http.StatusBadRequest, w.Code, "rule with empty group must be rejected")
}

// TestUpdateFirewall_RejectsOverlongGroup verifies that an over-long group
// string is rejected rather than marshaled into the config and pushed mesh-wide.
func TestUpdateFirewall_RejectsOverlongGroup(t *testing.T) {
	srv, testDB := newTestServer(t)

	op1Key, _, ca1 := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-fw-long-group",
		Name:  "Net FW Long Group",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	body, _ := json.Marshal(map[string]any{
		"inbound": []map[string]string{
			{"port": "22", "proto": "tcp", "group": strings.Repeat("a", maxGroupNameLen+1)},
		},
		"outbound": []map[string]string{
			{"port": "any", "proto": "any", "group": "any"},
		},
	})
	w := putFirewall(t, srv, op1Key, net1.ID, body)

	assert.Equal(t, http.StatusBadRequest, w.Code, "rule with over-long group must be rejected")
}

// TestUpdateFirewall_AcceptsValidGroup guards against over-zealous validation:
// a well-formed rule at the length bound is still accepted.
func TestUpdateFirewall_AcceptsValidGroup(t *testing.T) {
	srv, testDB := newTestServer(t)

	op1Key, _, ca1 := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-fw-valid-group",
		Name:  "Net FW Valid Group",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	body, _ := json.Marshal(map[string]any{
		"inbound": []map[string]string{
			{"port": "22", "proto": "tcp", "group": strings.Repeat("a", maxGroupNameLen)},
		},
		"outbound": []map[string]string{
			{"port": "any", "proto": "any", "group": "any"},
		},
	})
	w := putFirewall(t, srv, op1Key, net1.ID, body)

	assert.Equal(t, http.StatusOK, w.Code, "well-formed rule at the length bound must be accepted")
}
