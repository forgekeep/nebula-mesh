package api

import (
	"context"
	"net/http"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/mobileconfig"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// SEC-TENANT-001: a non-owner cannot read mobile settings for a foreign network.
func TestGetMobileConfig_NonOwnerDoesNotLeak(t *testing.T) {
	srv, st := newTestServer(t)
	_, _, ownerCA := createOperatorWithCA(t, srv)
	foreignKey, _, _ := createOperatorWithCA(t, srv)
	network := mobileConfigNetwork(t, st, ownerCA.ID)
	require.NoError(t, st.SetNetworkConfig(context.Background(), network.ID, mobileconfig.StoreKey,
		`{"dns_resolvers":["192.0.2.53"],"match_domains":["secret.example"],"allow_private_remotes":true}`))

	response := mobileConfigRequest(t, srv, http.MethodGet,
		"/api/v1/networks/"+network.ID+"/mobile-config", nil, foreignKey)
	assert.Equal(t, http.StatusForbidden, response.Code)
	assert.NotContains(t, response.Body.String(), "secret.example")
}

// SEC-TENANT-001: a non-owner cannot mutate mobile settings for a foreign network.
func TestPutMobileConfig_NonOwnerCannotMutate(t *testing.T) {
	srv, st := newTestServer(t)
	_, _, ownerCA := createOperatorWithCA(t, srv)
	foreignKey, _, _ := createOperatorWithCA(t, srv)
	network := mobileConfigNetwork(t, st, ownerCA.ID)

	response := mobileConfigRequest(t, srv, http.MethodPut,
		"/api/v1/networks/"+network.ID+"/mobile-config",
		[]byte(`{"dns_resolvers":[],"match_domains":[],"allow_private_remotes":false}`), foreignKey)
	assert.Equal(t, http.StatusForbidden, response.Code)
	_, err := st.GetNetworkConfig(context.Background(), network.ID, mobileconfig.StoreKey)
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestMobileConfig_OwnerCanReadAndMutate(t *testing.T) {
	srv, st := newTestServer(t)
	ownerKey, _, ownerCA := createOperatorWithCA(t, srv)
	network := mobileConfigNetwork(t, st, ownerCA.ID)
	path := "/api/v1/networks/" + network.ID + "/mobile-config"

	put := mobileConfigRequest(t, srv, http.MethodPut, path,
		[]byte(`{"dns_resolvers":[],"match_domains":[],"allow_private_remotes":false}`), ownerKey)
	assert.Equal(t, http.StatusOK, put.Code, put.Body.String())
	get := mobileConfigRequest(t, srv, http.MethodGet, path, nil, ownerKey)
	assert.Equal(t, http.StatusOK, get.Code, get.Body.String())
}

func mobileConfigNetwork(t *testing.T, st *store.SQLiteStore, caID string) *models.Network {
	t.Helper()
	network := &models.Network{
		ID: uuid.NewV4().String(), Name: "mobile-config-network", CAID: caID,
		CIDRs: []string{"10.55.0.0/16"}, CreatedAt: time.Now(),
	}
	require.NoError(t, st.CreateNetwork(context.Background(), network))
	return network
}
