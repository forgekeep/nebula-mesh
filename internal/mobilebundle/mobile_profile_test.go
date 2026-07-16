package mobilebundle

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	nebcfg "github.com/slackhq/nebula/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/mobileconfig"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// SEC-PERSIST-001: a mobile bundle must carry the durable CA blocklist so a
// revoked peer cannot regain access through a newly generated profile.
func TestBuild_SEC_PERSIST_001IncludesCurrentBlocklistAndEnrolledRelays(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s, resolver, network, host := newMobileFixture(t, "state")
	now := time.Now()
	for _, peer := range []*models.Host{
		{
			ID: "relay-enrolled", Name: "relay-enrolled", NetworkID: network.ID,
			NebulaIPs: []string{"10.0.0.20", "fd00::20"}, Role: models.HostRoleRelay,
			IsRelay: true, Status: models.HostStatusEnrolled, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "relay-pending", Name: "relay-pending", NetworkID: network.ID,
			NebulaIPs: []string{"10.0.0.30"}, Role: models.HostRoleRelay,
			IsRelay: true, Status: models.HostStatusPending, CreatedAt: now, UpdatedAt: now,
		},
		{
			ID: "ordinary-enrolled", Name: "ordinary-enrolled", NetworkID: network.ID,
			NebulaIPs: []string{"10.0.0.40"}, Role: models.HostRoleHost,
			Status: models.HostStatusEnrolled, CreatedAt: now, UpdatedAt: now,
		},
	} {
		require.NoError(t, s.CreateHost(ctx, peer))
	}
	require.NoError(t, s.AddToBlocklist(ctx, "revoked-fingerprint", "", "test"))

	settingsJSON, err := json.Marshal(mobileconfig.Settings{
		DNSResolvers:        []string{"10.0.0.53"},
		MatchDomains:        []string{},
		AllowPrivateRemotes: false,
	})
	require.NoError(t, err)
	require.NoError(t, s.SetNetworkConfig(ctx, network.ID, mobileconfig.StoreKey, string(settingsJSON)))

	bundle, err := Build(ctx, s, resolver, host)
	require.NoError(t, err)
	c := loadBundle(t, bundle)

	assert.Equal(t, []string{"revoked-fingerprint"}, c.GetStringSlice("pki.blocklist", nil))
	assert.Equal(t, []string{"10.0.0.20", "fd00::20"}, c.GetStringSlice("relay.relays", nil))
	assert.Equal(t, []string{"10.0.0.53"}, c.GetStringSlice("mobile_nebula.dns_resolvers", nil))
	assert.Equal(t, false, c.GetMap("lighthouse.remote_allow_list", nil)["10.0.0.0/8"])
}

func TestBuild_SEC_PERSIST_001InvalidSettingsDoNotEnrollOrRotateCertificate(t *testing.T) {
	t.Parallel()

	t.Run("pending host", func(t *testing.T) {
		ctx := context.Background()
		s, resolver, network, host := newMobileFixture(t, "pending")
		require.NoError(t, s.SetNetworkConfig(ctx, network.ID, mobileconfig.StoreKey, `{invalid`))

		bundle, err := Build(ctx, s, resolver, host)
		require.ErrorContains(t, err, "mobile config")
		assert.Nil(t, bundle)

		stored, getErr := s.GetHost(ctx, host.ID)
		require.NoError(t, getErr)
		assert.Equal(t, models.HostStatusPending, stored.Status)
		assert.Empty(t, stored.CertFingerprint)
		_, certErr := s.GetCertificateInfo(ctx, host.ID)
		require.ErrorIs(t, certErr, store.ErrNotFound)
	})

	t.Run("enrolled host", func(t *testing.T) {
		ctx := context.Background()
		s, resolver, network, host := newMobileFixture(t, "rotate")
		_, err := Build(ctx, s, resolver, host)
		require.NoError(t, err)
		before, err := s.GetHost(ctx, host.ID)
		require.NoError(t, err)

		require.NoError(t, s.SetNetworkConfig(ctx, network.ID, mobileconfig.StoreKey, `{invalid`))
		bundle, err := Build(ctx, s, resolver, before)
		require.ErrorContains(t, err, "mobile config")
		assert.Nil(t, bundle)

		after, getErr := s.GetHost(ctx, host.ID)
		require.NoError(t, getErr)
		assert.Equal(t, before.CertFingerprint, after.CertFingerprint)
	})
}

func TestListLighthousesFormatsIPv6PublicAddress(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s, _, network, _ := newMobileFixture(t, "ipv6")
	require.NoError(t, s.CreateHost(ctx, &models.Host{
		ID: "lighthouse-v6", Name: "lighthouse-v6", NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.1"}, Role: models.HostRoleLighthouse,
		IsLighthouse: true, PublicIP: "2001:db8::1", ListenPort: 4244,
		Status: models.HostStatusEnrolled, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}))

	lighthouses, err := listLighthouses(ctx, s, network.ID)
	require.NoError(t, err)
	require.Len(t, lighthouses, 1)
	assert.Equal(t, "[2001:db8::1]:4244", lighthouses[0].PublicAddr)
}

func newMobileFixture(t *testing.T, suffix string) (*store.SQLiteStore, *StubCAResolver, *models.Network, *models.Host) {
	t.Helper()

	ctx := context.Background()
	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	require.NoError(t, s.Migrate(ctx))

	ca, err := pki.NewCA("test-ca-"+suffix, 365*24*time.Hour)
	require.NoError(t, err)
	resolver := &StubCAResolver{ca: ca}
	network := &models.Network{
		ID: "net-" + suffix, Name: "network-" + suffix,
		CIDRs: []string{"10.0.0.0/8", "fd00::/8"},
	}
	require.NoError(t, s.CreateNetwork(ctx, network))
	host := &models.Host{
		ID: "mobile-" + suffix, Name: "phone-" + suffix, NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.5"}, Kind: models.HostKindMobile,
		Variant: models.HostVariantAndroid, Role: models.HostRoleHost,
		Status: models.HostStatusPending, CAID: "ca-" + suffix,
	}
	require.NoError(t, s.CreateHost(ctx, host))
	seedActiveCAOwner(t, s, host.CAID)
	return s, resolver, network, host
}

func loadBundle(t *testing.T, bundle []byte) *nebcfg.C {
	t.Helper()

	var c nebcfg.C
	require.NoError(t, c.LoadString(string(bundle)))
	return &c
}
