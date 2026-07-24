package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestCreateHost_RejectsInvalidFirewallInbound: advanced.firewall_inbound is
// validated at create time with the same friendly errors as the web form.
func TestCreateHost_RejectsInvalidFirewallInbound(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "bad-fw",
		NebulaIPs: []string{"192.168.100.30"},
		Role:      "host",
		Advanced: &models.HostAdvanced{
			FirewallInbound: []models.HostFirewallRule{
				{Port: "443", Proto: "sctp", Group: "web"},
			},
		},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
	require.True(t, strings.Contains(w.Body.String(), "advanced.firewall_inbound[0]"),
		"error should reference the offending rule: %s", w.Body.String())
}

// TestUpdateHost_FirewallInbound_AuditAndRepublish: a PATCH that only
// changes advanced.firewall_inbound must produce an audit diff entry and
// reset the host's config version so the agent re-renders on next poll.
func TestUpdateHost_FirewallInbound_AuditAndRepublish(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	host := createHostHelper(t, srv, netID, "fw-edit", "192.168.100.31", nil)

	// Simulate an agent that already consumed config version 5.
	require.NoError(t, srv.store.UpdateHostConfigVersion(ctx, host.ID, 5))

	reqBody, _ := json.Marshal(updateHostRequest{
		Advanced: &models.HostAdvanced{
			FirewallInbound: []models.HostFirewallRule{
				{Port: "22", Proto: "tcp", Group: "admin"},
			},
		},
	})
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+host.ID, bytes.NewBuffer(reqBody))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var updated models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updated))
	require.NotNil(t, updated.Advanced)
	require.Equal(t, []models.HostFirewallRule{{Port: "22", Proto: "tcp", Group: "admin"}},
		updated.Advanced.FirewallInbound)

	// Audit entry carries the advanced.firewall_inbound diff.
	entries, err := srv.store.ListAuditEntries(ctx, store.AuditFilter{Action: "host.update", Limit: 10})
	require.NoError(t, err)
	require.Equal(t, 1, len(entries))
	var details map[string]map[string]any
	require.NoError(t, json.Unmarshal([]byte(entries[0].Details), &details))
	require.Contains(t, details, "advanced.firewall_inbound")

	// Config version reset → re-render on next poll.
	version, err := srv.store.GetHostConfigVersion(ctx, host.ID)
	require.NoError(t, err)
	require.Equal(t, 0, version, "config version should reset so the agent re-renders")
}
