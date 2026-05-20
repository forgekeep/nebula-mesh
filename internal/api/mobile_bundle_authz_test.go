package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMobileBundle_RequiresOwnership verifies that non-owners cannot request
// a mobile bundle for a host they don't own (GHSA-598g-h2vc-h5vg, public
// issue #119).
func TestMobileBundle_RequiresOwnership(t *testing.T) {
	srv, testDB := newTestServer(t)

	// op1 owns ca1 and host1; op2 has its own CA and tries to fetch op1's bundle.
	_, _, ca1 := createOperatorWithCA(t, srv)
	op2Key, _, _ := createOperatorWithCA(t, srv)

	net1 := &models.Network{
		ID:    "net-mb-1",
		Name:  "Net MB 1",
		CAID:  ca1.ID,
		CIDRs: []string{"10.0.0.0/8"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net1))

	host1 := &models.Host{
		ID:        "host-mb-1",
		Name:      "Host MB 1",
		NetworkID: net1.ID,
		CAID:      ca1.ID,
		Kind:      models.HostKindMobile,
		NebulaIPs: []string{"10.0.0.5"},
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host1))

	// op2 tries to request mobile bundle for op1's host → 403
	req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/hosts/%s/mobile-bundle", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not get mobile bundle for foreign host")
}
