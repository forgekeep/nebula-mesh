package mobilebundle

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// wipeFixture builds an in-memory store + CA + mobile host. The returned CA's
// RawKey aliases the manager's live plaintext signing key, so the caller can
// assert it reads as zeros after Build wipes it.
func wipeFixture(t *testing.T, nebulaIPs []string) (context.Context, store.Store, *StubCAResolver, *models.Host, []byte) {
	t.Helper()
	ctx := context.Background()

	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	require.NoError(t, s.Migrate(ctx))

	ca, err := pki.NewCA("test-ca", 365*24*time.Hour)
	require.NoError(t, err)

	key := ca.RawKey()
	require.NotEmpty(t, key)
	require.False(t, allZero(key), "CA key already zero before Build — fixture broken")

	network := &models.Network{ID: "net-1", Name: "test-network", CIDRs: []string{"10.0.0.0/8"}}
	require.NoError(t, s.CreateNetwork(ctx, network))

	host := &models.Host{
		ID:        "mobile-1",
		Name:      "phone-a",
		NetworkID: network.ID,
		NebulaIPs: nebulaIPs,
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      "test-ca-id",
		Groups:    []string{"mobile"},
	}
	require.NoError(t, s.CreateHost(ctx, host))
	seedActiveCAOwner(t, s, host.CAID)

	return ctx, s, &StubCAResolver{ca: ca}, host, key
}

// TestBuild_WipesCAKeyOnSuccess covers GHSA-2p2f-px33-4vv5: Build must zeroize
// the plaintext CA signing key it decrypts via the resolver, so it does not
// linger on the heap after a successful mobile-bundle issuance.
func TestBuild_WipesCAKeyOnSuccess(t *testing.T) {
	ctx, s, resolver, host, key := wipeFixture(t, []string{"10.0.0.5"})

	bundle, err := Build(ctx, s, resolver, host)
	require.NoError(t, err)
	require.NotEmpty(t, bundle)

	require.True(t, allZero(key), "Build did not wipe the CA signing key on the success path")
}

// TestBuild_WipesCAKeyOnError covers the error paths after the CA is decrypted:
// an invalid prefix fails buildHostPrefixes after LoadByID, and the key must
// still be zeroized on return.
func TestBuild_WipesCAKeyOnError(t *testing.T) {
	// NebulaIP outside the network CIDR makes buildHostPrefixes fail, which
	// runs after the resolver has decrypted the CA key.
	ctx, s, resolver, host, key := wipeFixture(t, []string{"192.168.1.1"})

	_, err := Build(ctx, s, resolver, host)
	require.Error(t, err)

	require.True(t, allZero(key), "Build did not wipe the CA signing key on the error path")
}
