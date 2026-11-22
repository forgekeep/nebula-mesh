package mobilebundle

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// SEC-SECRET-001: invalid input is rejected before the signer is needed.
func TestBuildRejectsInvalidPrefixesBeforeSigning(t *testing.T) {
	ctx := context.Background()

	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	require.NoError(t, s.Migrate(ctx))

	network := &models.Network{ID: "net-1", Name: "test-network", CIDRs: []string{"10.0.0.0/8"}}
	require.NoError(t, s.CreateNetwork(ctx, network))

	host := &models.Host{
		ID:        "mobile-1",
		Name:      "phone-a",
		NetworkID: network.ID,
		NebulaIPs: []string{"192.0.2.1"},
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      "test-ca-id",
		Groups:    []string{"mobile"},
	}
	require.NoError(t, s.CreateHost(ctx, host))
	seedActiveCAOwner(t, s, host.CAID)

	_, err = Build(ctx, s, nil, host)
	require.ErrorContains(t, err, "build host prefixes")
}
