package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func patchHost(t *testing.T, srv *Server, hostID string, body updateHostRequest) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+hostID, bytes.NewBuffer(raw))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func renderedStaticHostMap(t *testing.T, srv *Server, host *models.Host) map[string][]string {
	t.Helper()
	cfg, err := srv.renderHostConfig(context.Background(), host)
	require.NoError(t, err)
	var parsed struct {
		StaticHostMap map[string][]string `yaml:"static_host_map"`
	}
	require.NoError(t, yaml.Unmarshal(cfg, &parsed))
	return parsed.StaticHostMap
}

// TestUpdateHost_LighthouseExtraEndpointsReachPeers: a peer on the
// lighthouse's LAN can only build a tunnel if its static_host_map carries the
// LAN endpoint, so setting extra_endpoints has to land in every peer's config
// and re-publish the network for agents to fetch it.
func TestUpdateHost_LighthouseExtraEndpointsReachPeers(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	enrollLighthouse(t, srv, netID, "lh1", "lighthouse", "192.168.100.1", "203.0.113.10", "fp-lh")
	peer := &models.Host{
		ID: "peer1", NetworkID: netID, Name: "peer",
		NebulaIPs: []string{"192.168.100.10"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	require.NoError(t, srv.store.CreateHost(ctx, peer))
	require.Equal(t, []string{"203.0.113.10:4242"}, renderedStaticHostMap(t, srv, peer)["192.168.100.1"])

	initial, err := srv.store.GetNetworkConfigVersion(ctx, netID)
	require.NoError(t, err)

	rec := patchHost(t, srv, "lh1", updateHostRequest{
		Advanced: &models.HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242", "[2001:db8::10]:4242"}},
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	bumped, err := srv.store.GetNetworkConfigVersion(ctx, netID)
	require.NoError(t, err)
	require.Greater(t, bumped, initial, "peers must be told to fetch the new static_host_map")
	require.Equal(t,
		[]string{"203.0.113.10:4242", "192.168.1.10:4242", "[2001:db8::10]:4242"},
		renderedStaticHostMap(t, srv, peer)["192.168.100.1"])
}

func TestUpdateHost_ExtraEndpointsRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	enrollLighthouse(t, srv, netID, "lh1", "lighthouse", "192.168.100.1", "203.0.113.10", "fp-lh")
	plain := createHostHelper(t, srv, netID, "web-1", "192.168.100.20", nil)
	hostRole := "host"

	tests := []struct {
		name   string
		hostID string
		body   updateHostRequest
		want   string
	}{
		{"not a lighthouse", plain.ID, updateHostRequest{
			Advanced: &models.HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242"}},
		}, "requires the lighthouse role"},
		{"hostname instead of an address", "lh1", updateHostRequest{
			Advanced: &models.HostAdvanced{ExtraEndpoints: []string{"lighthouse.lan:4242"}},
		}, "must be IP:PORT"},
		{"repeats the public endpoint", "lh1", updateHostRequest{
			Advanced: &models.HostAdvanced{ExtraEndpoints: []string{"203.0.113.10:4242"}},
		}, "repeats public_ip:listen_port"},
		{"listed twice", "lh1", updateHostRequest{
			Advanced: &models.HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242", "192.168.1.10:4242"}},
		}, "listed twice"},
		{"demoted while endpoints remain", "lh1", updateHostRequest{
			Role:     &hostRole,
			Advanced: &models.HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242"}},
		}, "requires the lighthouse role"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := patchHost(t, srv, tt.hostID, tt.body)
			require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			require.Contains(t, rec.Body.String(), tt.want)
		})
	}

	stored, err := srv.store.GetHost(context.Background(), "lh1")
	require.NoError(t, err)
	require.True(t, stored.IsLighthouse, "a rejected demotion must leave the lighthouse in place")
	require.Nil(t, stored.Advanced)
}

func TestCreateHost_ExtraEndpointsRequireLighthouse(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	adv := &models.HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242"}}

	create := func(name, ip, role, publicIP string) *httptest.ResponseRecorder {
		body, err := json.Marshal(createHostRequest{
			NetworkID: netID, Name: name, NebulaIPs: []string{ip}, Groups: []string{},
			Role: role, PublicIP: publicIP, ListenPort: 4242, Advanced: adv,
		})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
		authRequest(req)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	rec := create("web-1", "192.168.100.20", "host", "")
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), "requires the lighthouse role")

	rec = create("lh-1", "192.168.100.1", "lighthouse", "203.0.113.10")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var resp createHostResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.Equal(t, adv.ExtraEndpoints, resp.Host.Advanced.ExtraEndpoints)
}
