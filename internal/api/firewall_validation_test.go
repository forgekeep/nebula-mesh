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

// TestUpdateFirewall_CIDRSelectors covers the cidr / local_cidr rule fields on
// the network policy endpoint: a cidr may stand in for a group, local_cidr may
// accompany either, and the combinations Nebula would widen or reject are
// refused.
func TestUpdateFirewall_CIDRSelectors(t *testing.T) {
	cases := []struct {
		name     string
		inbound  map[string]string
		wantCode int
	}{
		{
			name:     "cidr instead of group",
			inbound:  map[string]string{"port": "443", "proto": "tcp", "cidr": "10.0.0.0/24"},
			wantCode: http.StatusOK,
		},
		{
			name:     "group with local_cidr",
			inbound:  map[string]string{"port": "443", "proto": "tcp", "group": "web", "local_cidr": "192.168.50.0/24"},
			wantCode: http.StatusOK,
		},
		{
			name:     "any is a valid cidr and local_cidr",
			inbound:  map[string]string{"port": "any", "proto": "any", "cidr": "any", "local_cidr": "any"},
			wantCode: http.StatusOK,
		},
		{
			name:     "ipv6 prefixes",
			inbound:  map[string]string{"port": "any", "proto": "any", "cidr": "fd00::/8", "local_cidr": "::/0"},
			wantCode: http.StatusOK,
		},
		{
			// Nebula OR's the peer selectors, so a rule carrying both matches
			// more than either alone.
			name:     "group and cidr together rejected",
			inbound:  map[string]string{"port": "443", "proto": "tcp", "group": "web", "cidr": "10.0.0.0/24"},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "local_cidr alone is not a selector",
			inbound:  map[string]string{"port": "443", "proto": "tcp", "local_cidr": "10.0.0.0/24"},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "unparseable cidr rejected",
			inbound:  map[string]string{"port": "443", "proto": "tcp", "cidr": "10.0.0.0/33"},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "bare IP as cidr rejected",
			inbound:  map[string]string{"port": "443", "proto": "tcp", "cidr": "10.0.0.1"},
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "unparseable local_cidr rejected",
			inbound:  map[string]string{"port": "443", "proto": "tcp", "group": "web", "local_cidr": "nope"},
			wantCode: http.StatusBadRequest,
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, testDB := newTestServer(t)
			opKey, _, ca := createOperatorWithCA(t, srv)
			net := &models.Network{
				ID:    fmt.Sprintf("net-fw-cidr-%d", i),
				Name:  fmt.Sprintf("Net FW CIDR %d", i),
				CAID:  ca.ID,
				CIDRs: []string{"10.0.0.0/8"},
			}
			require.NoError(t, testDB.CreateNetwork(context.Background(), net))

			body, _ := json.Marshal(map[string]any{
				"inbound":  []map[string]string{tc.inbound},
				"outbound": []map[string]string{{"port": "any", "proto": "any", "group": "any"}},
			})
			w := putFirewall(t, srv, opKey, net.ID, body)
			assert.Equal(t, tc.wantCode, w.Code, "rule %v", tc.inbound)
		})
	}
}

// TestUpdateFirewall_CIDRRulesRoundTripThroughGet verifies the new fields
// survive the store round-trip and are echoed back by GET, so an operator
// editing an existing policy does not silently drop them.
func TestUpdateFirewall_CIDRRulesRoundTripThroughGet(t *testing.T) {
	srv, testDB := newTestServer(t)
	opKey, _, ca := createOperatorWithCA(t, srv)
	net := &models.Network{
		ID:    "net-fw-cidr-roundtrip",
		Name:  "Net FW CIDR Roundtrip",
		CAID:  ca.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net))

	body, _ := json.Marshal(map[string]any{
		"inbound": []map[string]string{
			{"port": "443", "proto": "tcp", "cidr": "10.0.0.0/24"},
			{"port": "22", "proto": "tcp", "group": "admin", "local_cidr": "192.168.50.0/24"},
		},
		"outbound": []map[string]string{{"port": "any", "proto": "any", "group": "any"}},
	})
	require.Equal(t, http.StatusOK, putFirewall(t, srv, opKey, net.ID, body).Code)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/networks/%s/firewall", net.ID), nil)
	req.Header.Set("Authorization", "Bearer "+opKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var got firewallRulesRequest
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Len(t, got.Inbound, 2)
	assert.Equal(t, "10.0.0.0/24", got.Inbound[0].Cidr)
	assert.Empty(t, got.Inbound[0].Group, "a cidr-selected rule must not gain a group")
	assert.Equal(t, "admin", got.Inbound[1].Group)
	assert.Equal(t, "192.168.50.0/24", got.Inbound[1].LocalCidr)
}
