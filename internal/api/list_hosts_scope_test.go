package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestListHosts_NonAdminNotUndercountedPastLimit reproduces work-yzu3: with
// more hosts under CAs the caller does NOT own than the handler's 1000-row
// query cap, the caller's own host (sorting after that window) must still be
// returned. Previously the handler applied the owned-CA filter in Go AFTER the
// SQL LIMIT, so the owner's host was dropped from the window before the filter
// ran and the operator silently saw fewer hosts than they owned.
func TestListHosts_NonAdminNotUndercountedPastLimit(t *testing.T) {
	srv, st := newTestServer(t)
	keyB, _, caB := createOperatorWithCA(t, srv)
	ctx := context.Background()

	// One network for the foreign hosts (the host network_id FK); the ca_id on
	// the hosts is what scoping keys on.
	require.NoError(t, st.CreateNetwork(ctx, &models.Network{
		ID: "n-foreign", Name: "n-foreign", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}))
	// 1001 foreign hosts whose names sort before the owned host, so a global
	// "ORDER BY name LIMIT 1000" fills the entire window with them.
	for i := 0; i < 1001; i++ {
		require.NoError(t, st.CreateHost(ctx, &models.Host{
			ID: fmt.Sprintf("hf-%04d", i), NetworkID: "n-foreign", CAID: "ca-foreign",
			Name: fmt.Sprintf("aaa-%04d", i), Role: models.HostRoleHost, Status: models.HostStatusPending,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}))
	}
	// Operator B's single host, under a CA B owns, with a name that sorts last.
	require.NoError(t, st.CreateNetwork(ctx, &models.Network{
		ID: "n-mine", Name: "n-mine", CIDRs: []string{"10.1.0.0/24"}, CAID: caB.ID, CreatedAt: time.Now(),
	}))
	require.NoError(t, st.CreateHost(ctx, &models.Host{
		ID: "h-mine", NetworkID: "n-mine", CAID: caB.ID, Name: "zzz-mine",
		Role: models.HostRoleHost, Status: models.HostStatusPending, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer "+keyB)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var hosts []models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&hosts))
	// SEC-TENANT-001: the response must contain only the caller's owned host.
	require.Len(t, hosts, 1)
	require.Equal(t, "h-mine", hosts[0].ID)
	require.Equal(t, "zzz-mine", hosts[0].Name)
}
