package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestMobileBundle_RequiresOwnership verifies that non-owners cannot request
// a mobile bundle for a host they don't own (GHSA-598g-h2vc-h5vg, public
// issue #119) AND that the 403 is recorded as host.mobile_bundle.forbidden
// in the audit log.
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
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/hosts/%s/mobile-bundle", host1.ID), nil)
	req.Header.Set("Authorization", "Bearer "+op2Key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "non-owner should not get mobile bundle for foreign host")

	// Forbidden decision is recorded so an admin reading the audit log can
	// see who attempted the bundle on whose host.
	entries, err := testDB.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: auditHostMobileBundleForbidden,
		Limit:  10,
	})
	require.NoError(t, err)
	require.NotEmpty(t, entries, "expected at least one %s audit entry", auditHostMobileBundleForbidden)
	var found bool
	for _, e := range entries {
		if e.Resource == host1.ID {
			found = true
			assert.Equal(t, "non_owner", e.Details, "forbidden audit entry should carry reason")
			break
		}
	}
	assert.True(t, found, "expected %s audit entry for host %s", auditHostMobileBundleForbidden, host1.ID)
}

// TestMobileBundle_AdminCanAccessForeignHost confirms an admin operator can
// mint a mobile bundle for a host owned by a different operator's CA — the
// admin override path of canAccessHost — and that the successful issuance
// is recorded as host.mobile_bundle.issued.
func TestMobileBundle_AdminCanAccessForeignHost(t *testing.T) {
	srv, testDB := newTestServer(t)

	// Non-admin operator owns the CA and host; admin is the test server's
	// seeded test-admin (authenticated via authRequest / testAPIKey).
	_, _, ca := createOperatorWithCA(t, srv)

	net := &models.Network{
		ID:    "net-mb-admin-x",
		Name:  "Net MB Admin Cross",
		CAID:  ca.ID,
		CIDRs: []string{"10.20.0.0/16"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net))

	now := time.Now()
	host := &models.Host{
		ID:        uuid.New().String(),
		Name:      "iphone-cross",
		NetworkID: net.ID,
		CAID:      ca.ID,
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		NebulaIPs: []string{"10.20.0.5"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host))

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/hosts/%s/mobile-bundle", host.ID), nil)
	authRequest(req) // admin (testAPIKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code, "admin should mint mobile bundle for foreign-CA host; body=%s", w.Body.String())

	entries, err := testDB.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: auditHostMobileBundleIssued,
		Limit:  10,
	})
	require.NoError(t, err)
	var found bool
	for _, e := range entries {
		if e.Resource == host.ID {
			found = true
			assert.Equal(t, "ca_id="+ca.ID, e.Details, "issued audit entry should record ca_id")
			break
		}
	}
	assert.True(t, found, "expected %s audit entry for host %s", auditHostMobileBundleIssued, host.ID)
}

// TestMobileBundle_OwningNonAdminCanAccess confirms a non-admin operator
// can mint a mobile bundle for a host in their own CA — the CA-owner path
// of canAccessHost. ADR 0002 §4.2 preserves the per-operator-CA flow.
func TestMobileBundle_OwningNonAdminCanAccess(t *testing.T) {
	srv, testDB := newTestServer(t)

	opKey, _, ca := createOperatorWithCA(t, srv)

	net := &models.Network{
		ID:    "net-mb-own",
		Name:  "Net MB Own",
		CAID:  ca.ID,
		CIDRs: []string{"10.30.0.0/16"},
	}
	require.NoError(t, testDB.CreateNetwork(context.Background(), net))

	now := time.Now()
	host := &models.Host{
		ID:        uuid.New().String(),
		Name:      "iphone-own",
		NetworkID: net.ID,
		CAID:      ca.ID,
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantAndroid,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		NebulaIPs: []string{"10.30.0.5"},
		CreatedAt: now,
		UpdatedAt: now,
	}
	require.NoError(t, testDB.CreateHost(context.Background(), host))

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/v1/hosts/%s/mobile-bundle", host.ID), nil)
	req.Header.Set("Authorization", "Bearer "+opKey)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code, "CA owner (non-admin) should mint mobile bundle for own host; body=%s", w.Body.String())

	entries, err := testDB.ListAuditEntries(context.Background(), store.AuditFilter{
		Action: auditHostMobileBundleIssued,
		Limit:  10,
	})
	require.NoError(t, err)
	var found bool
	for _, e := range entries {
		if e.Resource == host.ID {
			found = true
			assert.Equal(t, "ca_id="+ca.ID, e.Details, "issued audit entry should record ca_id")
			break
		}
	}
	assert.True(t, found, "expected %s audit entry for host %s", auditHostMobileBundleIssued, host.ID)
}
