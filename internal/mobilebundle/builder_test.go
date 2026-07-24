package mobilebundle

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestBuild_RoundTrip(t *testing.T) {
	ctx := context.Background()

	// Setup: in-memory store, CA, network, mobile host.
	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	require.NotNil(t, s)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Create a CA.
	ca, err := pki.NewCA("test-ca", 365*24*time.Hour)
	require.NoError(t, err)

	// Create CA resolver (wrap ca in a stub that returns it by id).
	resolver := &StubCAResolver{ca: ca}

	// Create network.
	network := &models.Network{
		ID:    "net-1",
		Name:  "test-network",
		CIDRs: []string{"10.0.0.0/8"},
	}
	err = s.CreateNetwork(ctx, network)
	require.NoError(t, err)

	// Create mobile host.
	host := &models.Host{
		ID:        "mobile-1",
		Name:      "phone-a",
		NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.5"},
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      "test-ca-id", // stub resolver ignores this
		Groups:    []string{"mobile", "ios"},
	}
	err = s.CreateHost(ctx, host)
	require.NoError(t, err)
	seedActiveCAOwner(t, s, host.CAID)

	// Call Build.
	bundle, err := Build(ctx, s, resolver, host)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	require.NotEmpty(t, bundle)

	// Parse as YAML.
	var parsed map[string]interface{}
	err = yaml.Unmarshal(bundle, &parsed)
	require.NoError(t, err)

	// Check pki section exists and contains inline PEM.
	pkiRaw, ok := parsed["pki"]
	require.True(t, ok, "no pki section in bundle")
	pkiSection, ok := pkiRaw.(map[string]interface{})
	require.True(t, ok, "pki is not a map")

	// Check CA PEM.
	caRaw, ok := pkiSection["ca"]
	require.True(t, ok, "no ca in pki")
	caPEM, ok := caRaw.(string)
	require.True(t, ok, "ca is not a string")
	require.NotEmpty(t, caPEM)
	require.True(t,
		contains(caPEM, "-----BEGIN NEBULA CERTIFICATE-----") ||
			contains(caPEM, "-----BEGIN NEBULA CERTIFICATE V2-----"),
		"CA PEM does not have valid NEBULA CERTIFICATE header",
	)

	// Verify CA PEM is valid.
	caCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(caPEM))
	require.NoError(t, err)
	require.Equal(t, "test-ca", caCert.Name())

	// Check host cert PEM.
	certRaw, ok := pkiSection["cert"]
	require.True(t, ok, "no cert in pki")
	certPEM, ok := certRaw.(string)
	require.True(t, ok, "cert is not a string")
	require.NotEmpty(t, certPEM)

	hostCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(certPEM))
	require.NoError(t, err)
	require.Equal(t, "phone-a", hostCert.Name())
	require.Len(t, hostCert.Networks(), 1)
	require.Equal(t, "10.0.0.5/8", hostCert.Networks()[0].String())

	// Check key PEM.
	keyRaw, ok := pkiSection["key"]
	require.True(t, ok, "no key in pki")
	keyPEM, ok := keyRaw.(string)
	require.True(t, ok, "key is not a string")
	require.NotEmpty(t, keyPEM)

	privKey, _, _, err := cert.UnmarshalPrivateKeyFromPEM([]byte(keyPEM))
	require.NoError(t, err)
	require.NotNil(t, privKey)

	// Verify host is enrolled and has cert fingerprint.
	updated, err := s.GetHost(ctx, host.ID)
	require.NoError(t, err)
	require.Equal(t, models.HostStatusEnrolled, updated.Status)
	require.NotEmpty(t, updated.CertFingerprint)
	require.Empty(t, updated.SigningPubPEM) // Mobile should not have PoP key

	// Check that cert is in database.
	certInfo, err := s.GetCertificateInfo(ctx, host.ID)
	require.NoError(t, err)
	require.NotNil(t, certInfo)
	require.True(t, certInfo.IsCurrent)
}

func TestBuild_Rotate(t *testing.T) {
	ctx := context.Background()

	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	require.NotNil(t, s)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ca, err := pki.NewCA("test-ca", 365*24*time.Hour)
	require.NoError(t, err)
	resolver := &StubCAResolver{ca: ca}

	network := &models.Network{
		ID:    "net-1",
		Name:  "test-network",
		CIDRs: []string{"10.0.0.0/8"},
	}
	err = s.CreateNetwork(ctx, network)
	require.NoError(t, err)

	host := &models.Host{
		ID:        "mobile-1",
		Name:      "phone-a",
		NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.5"},
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantAndroid,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      "test-ca-id",
		Groups:    []string{"mobile"},
	}
	err = s.CreateHost(ctx, host)
	require.NoError(t, err)
	seedActiveCAOwner(t, s, host.CAID)

	// First call.
	bundle1, err := Build(ctx, s, resolver, host)
	require.NoError(t, err)

	host1, err := s.GetHost(ctx, host.ID)
	require.NoError(t, err)
	fp1 := host1.CertFingerprint

	// Second call (rotate).
	bundle2, err := Build(ctx, s, resolver, host1)
	require.NoError(t, err)

	host2, err := s.GetHost(ctx, host.ID)
	require.NoError(t, err)
	fp2 := host2.CertFingerprint

	// Fingerprints must differ.
	require.NotEqual(t, fp1, fp2)
	require.NotEmpty(t, fp1)
	require.NotEmpty(t, fp2)

	// Bundles should be different.
	require.NotEqual(t, string(bundle1), string(bundle2))

	// Both should be valid YAML.
	var p1, p2 map[string]interface{}
	require.NoError(t, yaml.Unmarshal(bundle1, &p1))
	require.NoError(t, yaml.Unmarshal(bundle2, &p2))
}

func TestBuild_RejectsNonMobile(t *testing.T) {
	ctx := context.Background()

	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	require.NotNil(t, s)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	ca, err := pki.NewCA("test-ca", 365*24*time.Hour)
	require.NoError(t, err)
	resolver := &StubCAResolver{ca: ca}

	network := &models.Network{
		ID:    "net-1",
		Name:  "test-network",
		CIDRs: []string{"10.0.0.0/8"},
	}
	err = s.CreateNetwork(ctx, network)
	require.NoError(t, err)

	// Agent host (not mobile).
	host := &models.Host{
		ID:        "agent-1",
		Name:      "server-a",
		NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.1"},
		Kind:      models.HostKindAgent,
		Variant:   models.HostVariantNone,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      "test-ca-id",
	}
	err = s.CreateHost(ctx, host)
	require.NoError(t, err)

	bundle, err := Build(ctx, s, resolver, host)
	require.ErrorIs(t, err, ErrNotMobile)
	require.Nil(t, bundle)
}

// seedActiveCAOwner inserts an active operator plus a CA row with id caID owned
// by it, so Build's durable-revocation check (GHSA-339v-266x-79xr) sees a live
// owner. The StubCAResolver still supplies the actual signing CA.
func seedActiveCAOwner(t *testing.T, s store.Store, caID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	if err := s.CreateOperator(ctx, &models.Operator{
		ID: "op-1", Username: "op-1", PasswordHash: "hash", Role: "admin",
		Status: models.OperatorStatusActive, AuthProvider: models.OperatorAuthLocal,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed operator: %v", err)
	}
	if err := s.CreateCA(ctx, &models.CA{
		ID: caID, Name: caID, OwnerOperatorID: "op-1", Fingerprint: "fp-" + caID,
		CertPEM: "stub", Status: models.CAStatusActive, NotBefore: now, NotAfter: now.Add(time.Hour),
		EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("n"),
		EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed CA: %v", err)
	}
}

// StubCAResolver returns a fixed CA for any ID.
type StubCAResolver struct {
	ca *pki.CAManager
}

func (s *StubCAResolver) LoadByID(ctx context.Context, caID string) (*pki.CAManager, error) {
	return s.ca, nil
}

func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestBuild_AppliesStoredFirewallRules pins that a mobile bundle carries the
// network's stored firewall policy, the same as the agent enroll path. Before
// the M1 fix the builder hardcoded icmp-inbound/allow-all-outbound, so a
// configured policy never reached mobile hosts either.
func TestBuild_AppliesStoredFirewallRules(t *testing.T) {
	ctx := context.Background()

	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	require.NoError(t, s.Migrate(ctx))

	ca, err := pki.NewCA("test-ca", 365*24*time.Hour)
	require.NoError(t, err)
	resolver := &StubCAResolver{ca: ca}

	network := &models.Network{ID: "net-fw", Name: "fw-network", CIDRs: []string{"10.0.0.0/8"}}
	require.NoError(t, s.CreateNetwork(ctx, network))

	const policy = `{"inbound":[{"port":"8443","proto":"tcp","group":"mobile-only"}],` +
		`"outbound":[{"port":"any","proto":"any","group":"any"}]}`
	require.NoError(t, s.SetNetworkConfig(ctx, network.ID, "firewall", policy))

	host := &models.Host{
		ID: "mobile-fw", Name: "phone-fw", NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.9"}, Kind: models.HostKindMobile,
		Variant: models.HostVariantIOS, Role: models.HostRoleHost,
		Status: models.HostStatusPending, CAID: "test-ca-id", Groups: []string{"mobile"},
	}
	require.NoError(t, s.CreateHost(ctx, host))
	seedActiveCAOwner(t, s, host.CAID)

	bundle, err := Build(ctx, s, resolver, host)
	require.NoError(t, err)
	if !strings.Contains(string(bundle), "mobile-only") {
		t.Errorf("mobile bundle does not contain the stored firewall group; rules not applied\n%s", bundle)
	}
}

// TestBuild_AppendsHostFirewallInbound: per-host inbound rules must reach
// the mobile bundle too, appended after the network policy.
func TestBuild_AppendsHostFirewallInbound(t *testing.T) {
	ctx := context.Background()

	s, err := store.NewSQLiteStore(":memory:")
	require.NoError(t, err)
	require.NoError(t, s.Migrate(ctx))

	ca, err := pki.NewCA("test-ca", 365*24*time.Hour)
	require.NoError(t, err)
	resolver := &StubCAResolver{ca: ca}

	network := &models.Network{ID: "net-hfw", Name: "hfw-network", CIDRs: []string{"10.0.0.0/8"}}
	require.NoError(t, s.CreateNetwork(ctx, network))

	const policy = `{"inbound":[{"port":"8443","proto":"tcp","group":"mobile-only"}],` +
		`"outbound":[{"port":"any","proto":"any","group":"any"}]}`
	require.NoError(t, s.SetNetworkConfig(ctx, network.ID, "firewall", policy))

	host := &models.Host{
		ID: "mobile-hfw", Name: "phone-hfw", NetworkID: network.ID,
		NebulaIPs: []string{"10.0.0.10"}, Kind: models.HostKindMobile,
		Variant: models.HostVariantIOS, Role: models.HostRoleHost,
		Status: models.HostStatusPending, CAID: "test-ca-id", Groups: []string{"mobile"},
		Advanced: &models.HostAdvanced{
			FirewallInbound: []models.HostFirewallRule{
				{Port: "5000", Proto: "udp", Group: "sync-peers"},
			},
		},
	}
	require.NoError(t, s.CreateHost(ctx, host))
	seedActiveCAOwner(t, s, host.CAID)

	bundle, err := Build(ctx, s, resolver, host)
	require.NoError(t, err)
	out := string(bundle)
	if !strings.Contains(out, "mobile-only") {
		t.Errorf("network firewall rule missing from bundle\n%s", out)
	}
	if !strings.Contains(out, "sync-peers") {
		t.Errorf("per-host firewall rule missing from bundle\n%s", out)
	}
	if netIdx, hostIdx := strings.Index(out, "mobile-only"), strings.Index(out, "sync-peers"); netIdx > hostIdx {
		t.Errorf("network rule should render before the per-host rule\n%s", out)
	}
}
