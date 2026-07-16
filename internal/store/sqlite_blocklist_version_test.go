package store

import (
	"context"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

type caScopedVersionFixture struct {
	store    *SQLiteStore
	primary  *models.Network
	sibling  *models.Network
	other    *models.Network
	host     *models.Host
	versions map[string]int
}

func newCAScopedVersionFixture(t *testing.T) caScopedVersionFixture {
	t.Helper()
	store := newTestStore(t)
	operator, ca, primary, now := seedMeshImportScope(t, store)
	sibling := &models.Network{
		ID: "network-a-2", Name: "network-a-2", CIDRs: []string{"10.43.0.0/16"}, CAID: ca.ID, CreatedAt: now,
	}
	if err := store.CreateNetwork(t.Context(), sibling); err != nil {
		t.Fatal(err)
	}
	otherCA := meshImportCA("ca-b", "ca-b-fingerprint", operator.ID, nil, now)
	if err := store.CreateCA(t.Context(), otherCA); err != nil {
		t.Fatal(err)
	}
	other := &models.Network{
		ID: "network-b", Name: "network-b", CIDRs: []string{"10.44.0.0/16"}, CAID: otherCA.ID, CreatedAt: now,
	}
	if err := store.CreateNetwork(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	host := &models.Host{
		ID: "host-a", NetworkID: primary.ID, CAID: ca.ID, Name: "host-a", NebulaIPs: []string{"10.42.0.10"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CertFingerprint: tokenHash("host-a-certificate"), CreatedAt: now, UpdatedAt: now,
	}
	if err := store.CreateHost(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateHost(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	fixture := caScopedVersionFixture{store: store, primary: primary, sibling: sibling, other: other, host: host}
	fixture.versions = fixture.readVersions(t)
	return fixture
}

func (fixture caScopedVersionFixture) readVersions(t *testing.T) map[string]int {
	t.Helper()
	versions := make(map[string]int, 3)
	for _, network := range []*models.Network{fixture.primary, fixture.sibling, fixture.other} {
		version, err := fixture.store.GetNetworkConfigVersion(t.Context(), network.ID)
		if err != nil {
			t.Fatal(err)
		}
		versions[network.ID] = version
	}
	return versions
}

func (fixture caScopedVersionFixture) requireDeltas(t *testing.T, before map[string]int, primary, sibling, other int) {
	t.Helper()
	after := fixture.readVersions(t)
	wants := map[string]int{fixture.primary.ID: primary, fixture.sibling.ID: sibling, fixture.other.ID: other}
	for networkID, delta := range wants {
		if after[networkID] != before[networkID]+delta {
			t.Fatalf("network %s version = %d, want %d", networkID, after[networkID], before[networkID]+delta)
		}
	}
}

func TestBlockHostAndAddToBlocklistBumpsEveryNetworkForCA(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	if _, err := fixture.store.BlockHostAndAddToBlocklist(t.Context(), fixture.host.ID, "test"); err != nil {
		t.Fatal(err)
	}
	fixture.requireDeltas(t, fixture.versions, 1, 1, 0)
}

func TestDeleteHostAndBlockCertBumpsEveryNetworkForCA(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	if err := fixture.store.DeleteHostAndBlockCert(t.Context(), fixture.host.ID, "test"); err != nil {
		t.Fatal(err)
	}
	fixture.requireDeltas(t, fixture.versions, 1, 1, 0)
}

func TestUnblockHostAndRemoveFromBlocklistBumpsEveryNetworkForCA(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	if _, err := fixture.store.BlockHostAndAddToBlocklist(t.Context(), fixture.host.ID, "test"); err != nil {
		t.Fatal(err)
	}
	before := fixture.readVersions(t)
	if _, err := fixture.store.UnblockHostAndRemoveFromBlocklist(t.Context(), fixture.host.ID); err != nil {
		t.Fatal(err)
	}
	fixture.requireDeltas(t, before, 1, 1, 0)
}

func TestUnblockHostWithoutBlocklistRowDoesNotBumpNetworks(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	if _, err := fixture.store.BlockHostAndAddToBlocklist(t.Context(), fixture.host.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.db.ExecContext(context.Background(), `DELETE FROM blocklist WHERE fingerprint = ?`, fixture.host.CertFingerprint); err != nil {
		t.Fatal(err)
	}
	before := fixture.readVersions(t)
	if _, err := fixture.store.UnblockHostAndRemoveFromBlocklist(t.Context(), fixture.host.ID); err != nil {
		t.Fatal(err)
	}
	fixture.requireDeltas(t, before, 0, 0, 0)
}

func TestBlockEnrolledLighthouseWithoutFingerprintBumpsOnlyOwnNetwork(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	if _, err := fixture.store.db.Exec(`DELETE FROM hosts WHERE id = ?`, fixture.host.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	lighthouse := &models.Host{
		ID: "lighthouse-a", NetworkID: fixture.primary.ID, CAID: fixture.primary.CAID, Name: "lighthouse-a",
		NebulaIPs: []string{"10.42.0.1"}, Groups: []string{}, Role: models.HostRoleLighthouse,
		IsLighthouse: true, PublicIP: "203.0.113.10", ListenPort: 4242,
		Status: models.HostStatusEnrolled, CreatedAt: now, UpdatedAt: now,
	}
	if err := fixture.store.CreateHost(t.Context(), lighthouse); err != nil {
		t.Fatal(err)
	}
	before := fixture.readVersions(t)
	if _, err := fixture.store.BlockHostAndAddToBlocklist(t.Context(), lighthouse.ID, "test"); err != nil {
		t.Fatal(err)
	}
	fixture.requireDeltas(t, before, 1, 0, 0)
}
