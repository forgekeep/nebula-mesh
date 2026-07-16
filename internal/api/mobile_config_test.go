package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/mobileconfig"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestMobileConfig_GetDefaultsAndPutNormalizedSettings(t *testing.T) {
	srv, st := newTestServer(t)
	networkID := createNetwork(t, srv)
	path := "/api/v1/networks/" + networkID + "/mobile-config"

	beforeVersion, err := st.GetNetworkConfigVersion(context.Background(), networkID)
	require.NoError(t, err)

	response := mobileConfigRequest(t, srv, http.MethodGet, path, nil, testAPIKey)
	assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
	assert.JSONEq(t, `{
		"dns_resolvers": [],
		"match_domains": [],
		"allow_private_remotes": true
	}`, response.Body.String())

	payload := []byte(`{
		"dns_resolvers": [" 10.0.0.53 ", "2001:0db8::53"],
		"match_domains": [" corp.example "],
		"allow_private_remotes": false
	}`)
	response = mobileConfigRequest(t, srv, http.MethodPut, path, payload, testAPIKey)
	assert.Equal(t, http.StatusOK, response.Code, response.Body.String())
	assert.JSONEq(t, `{
		"dns_resolvers": ["10.0.0.53", "2001:db8::53"],
		"match_domains": ["corp.example"],
		"allow_private_remotes": false
	}`, response.Body.String())

	stored, err := st.GetNetworkConfig(context.Background(), networkID, mobileconfig.StoreKey)
	require.NoError(t, err)
	settings, err := mobileconfig.Decode(stored)
	require.NoError(t, err)
	assert.Equal(t, []string{"10.0.0.53", "2001:db8::53"}, settings.DNSResolvers)

	afterVersion, err := st.GetNetworkConfigVersion(context.Background(), networkID)
	require.NoError(t, err)
	assert.Equal(t, beforeVersion, afterVersion, "mobile-only settings must not wake desktop agents")
}

func TestMobileConfig_PutRejectsInvalidJSONAndSettings(t *testing.T) {
	srv, _ := newTestServer(t)
	path := "/api/v1/networks/" + createNetwork(t, srv) + "/mobile-config"

	tests := []struct {
		name string
		body string
	}{
		{"missing field", `{"dns_resolvers":[],"match_domains":[]}`},
		{"unknown field", `{"dns_resolvers":[],"match_domains":[],"allow_private_remotes":true,"extra":1}`},
		{"trailing json", `{"dns_resolvers":[],"match_domains":[],"allow_private_remotes":true}{}`},
		{"invalid resolver", `{"dns_resolvers":["dns.example"],"match_domains":[],"allow_private_remotes":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := mobileConfigRequest(t, srv, http.MethodPut, path, []byte(tt.body), testAPIKey)
			assert.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
		})
	}
}

func TestMobileConfig_PutConflictsWithCollectingMeshImport(t *testing.T) {
	srv, st := newTestServer(t)
	key, operator, ca := createOperatorWithCA(t, srv)
	network := &models.Network{
		ID: uuid.NewString(), Name: "importing-network", CAID: ca.ID,
		CIDRs: []string{"10.44.0.0/16"}, CreatedAt: time.Now(),
	}
	require.NoError(t, st.CreateNetwork(context.Background(), network))
	require.NoError(t, st.CreateMeshImport(context.Background(), &models.MeshImport{
		ID: uuid.NewString(), NetworkID: network.ID, CAID: ca.ID,
		OwnerOperatorID: operator.ID, Status: models.MeshImportStatusCollecting,
		TokenHash: uuid.NewString(), TokenExpiresAt: time.Now().Add(time.Hour),
	}))

	response := mobileConfigRequest(t, srv, http.MethodPut,
		"/api/v1/networks/"+network.ID+"/mobile-config",
		[]byte(`{"dns_resolvers":[],"match_domains":[],"allow_private_remotes":true}`), key)
	assert.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	_, err := st.GetNetworkConfig(context.Background(), network.ID, mobileconfig.StoreKey)
	require.ErrorIs(t, err, store.ErrNotFound)
}

func TestMobileConfig_PutWritesAuditEntry(t *testing.T) {
	srv, st := newTestServer(t)
	networkID := createNetwork(t, srv)

	response := mobileConfigRequest(t, srv, http.MethodPut,
		"/api/v1/networks/"+networkID+"/mobile-config",
		[]byte(`{"dns_resolvers":["10.0.0.53"],"match_domains":[],"allow_private_remotes":true}`),
		testAPIKey)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())

	entries, err := st.ListAuditEntries(context.Background(), store.AuditFilter{Action: auditNetworkMobileConfigUpdate})
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, networkID, entries[0].Resource)
	var details mobileconfig.Settings
	require.NoError(t, json.Unmarshal([]byte(entries[0].Details), &details))
	assert.Equal(t, []string{"10.0.0.53"}, details.DNSResolvers)
}

func mobileConfigRequest(t *testing.T, srv *Server, method, path string, body []byte, key string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	recorder := httptest.NewRecorder()
	srv.ServeHTTP(recorder, req)
	return recorder
}
