package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/hostdns"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

const hostDNSBody = `{"nameservers":["10.0.0.53"],"match_domains":["Mesh.Example"],"search_domains":["web.mesh.example"]}`

func TestHostDNS_GetDefaultsAndPutBumpsNetwork(t *testing.T) {
	srv, st := newTestServer(t)
	networkID := createNetwork(t, srv)
	path := "/api/v1/networks/" + networkID + "/host-dns"

	get := mobileConfigRequest(t, srv, http.MethodGet, path, nil, testAPIKey)
	assert.Equal(t, http.StatusOK, get.Code, get.Body.String())
	assert.JSONEq(t, `{"nameservers":[],"match_domains":[],"search_domains":[]}`, get.Body.String())

	before, err := st.GetNetworkConfigVersion(context.Background(), networkID)
	require.NoError(t, err)
	put := mobileConfigRequest(t, srv, http.MethodPut, path, []byte(hostDNSBody), testAPIKey)
	assert.Equal(t, http.StatusOK, put.Code, put.Body.String())
	assert.JSONEq(t, `{"nameservers":["10.0.0.53"],"match_domains":["mesh.example"],"search_domains":["web.mesh.example"]}`, put.Body.String())

	after, err := st.GetNetworkConfigVersion(context.Background(), networkID)
	require.NoError(t, err)
	assert.Greater(t, after, before, "host DNS is rendered into agent configs, so agents must get it")
	assert.Equal(t, 1, countAudit(t, st, auditNetworkHostDNSUpdate, networkID))

	bad := mobileConfigRequest(t, srv, http.MethodPut, path,
		[]byte(`{"nameservers":["10.0.0.53"],"match_domains":[],"search_domains":[]}`), testAPIKey)
	assert.Equal(t, http.StatusBadRequest, bad.Code)
	assert.Contains(t, bad.Body.String(), "match_domains must list at least one domain")
}

// SEC-TENANT-001: a non-owner cannot read a foreign network's host DNS.
func TestGetHostDNS_SEC_TENANT_001_NonOwnerDoesNotLeak(t *testing.T) {
	srv, st := newTestServer(t)
	_, _, ownerCA := createOperatorWithCA(t, srv)
	foreignKey, _, _ := createOperatorWithCA(t, srv)
	network := mobileConfigNetwork(t, st, ownerCA.ID)
	require.NoError(t, st.SetNetworkConfig(context.Background(), network.ID, hostdns.StoreKey,
		`{"nameservers":["192.0.2.53"],"match_domains":["secret.example"],"search_domains":[]}`))

	response := mobileConfigRequest(t, srv, http.MethodGet, "/api/v1/networks/"+network.ID+"/host-dns", nil, foreignKey)
	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.NotContains(t, response.Body.String(), "secret.example")
}

// SEC-TENANT-001: a non-owner cannot change a foreign network's host DNS.
func TestPutHostDNS_SEC_TENANT_001_NonOwnerCannotMutate(t *testing.T) {
	srv, st := newTestServer(t)
	ownerKey, _, ownerCA := createOperatorWithCA(t, srv)
	foreignKey, _, _ := createOperatorWithCA(t, srv)
	network := mobileConfigNetwork(t, st, ownerCA.ID)
	path := "/api/v1/networks/" + network.ID + "/host-dns"

	response := mobileConfigRequest(t, srv, http.MethodPut, path, []byte(hostDNSBody), foreignKey)
	assert.Equal(t, http.StatusForbidden, response.Code)
	_, err := st.GetNetworkConfig(context.Background(), network.ID, hostdns.StoreKey)
	require.ErrorIs(t, err, store.ErrNotFound)

	owner := mobileConfigRequest(t, srv, http.MethodPut, path, []byte(hostDNSBody), ownerKey)
	assert.Equal(t, http.StatusOK, owner.Code, owner.Body.String())
}

// The stanza reaches a 1.12 macOS host and stays out of a Linux one.
func TestAgentConfig_RendersHostDNSForSupportedRuntime(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)
	host, err := st.GetHost(t.Context(), agent.hostID)
	require.NoError(t, err)
	put := mobileConfigRequest(t, srv, http.MethodPut, "/api/v1/networks/"+host.NetworkID+"/host-dns", []byte(hostDNSBody), testAPIKey)
	require.Equal(t, http.StatusOK, put.Code, put.Body.String())

	require.Equal(t, http.StatusOK, postRuntime(t, srv, agent, "/api/v1/agent/runtime/linux/1.12.0").Code)
	cfg := pollConfig(t, srv, agent)
	require.NotNil(t, cfg)
	assert.NotContains(t, *cfg, "nameservers", "linux host got the dns stanza")

	require.Equal(t, http.StatusOK, postRuntime(t, srv, agent, "/api/v1/agent/runtime/darwin/1.12.0").Code)
	cfg = pollConfig(t, srv, agent)
	require.NotNil(t, cfg)
	assert.True(t, strings.Contains(*cfg, "dns:") && strings.Contains(*cfg, "- 10.0.0.53") && strings.Contains(*cfg, "- mesh.example"),
		"darwin 1.12 host did not get the dns stanza:\n%s", *cfg)
}
