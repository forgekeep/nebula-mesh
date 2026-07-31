package store

import (
	"context"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func seedNetworkForUnsafe(t *testing.T, s *SQLiteStore) {
	t.Helper()
	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-1", Name: "net", CIDRs: []string{"172.31.16.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

// Order is part of the signed certificate body, so the store must preserve it
// rather than normalizing — otherwise a no-op read/write cycle would look like
// an edit and churn certificates mesh-wide. The fixture is deliberately not in
// sorted order so any reordering fails the index-by-index assertions.
func TestHost_UnsafeNetworksRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNetworkForUnsafe(t, s)

	want := []string{"192.168.1.0/24", "10.10.0.0/16"}
	host := &models.Host{
		ID: "h-gw", NetworkID: "n-1", Name: "gw",
		NebulaIPs:      []string{"172.31.16.250"},
		Groups:         []string{"sillero"},
		UnsafeNetworks: want,
		Role:           models.HostRoleHost,
		Status:         models.HostStatusEnrolled,
		CreatedAt:      time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatalf("CreateHost: %v", err)
	}

	stored, err := s.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatalf("GetHost: %v", err)
	}
	if len(stored.UnsafeNetworks) != len(want) {
		t.Fatalf("unsafe networks = %v, want %v", stored.UnsafeNetworks, want)
	}
	for i := range want {
		if stored.UnsafeNetworks[i] != want[i] {
			t.Errorf("unsafe networks[%d] = %q, want %q", i, stored.UnsafeNetworks[i], want[i])
		}
	}
}

// A host that advertises nothing is the common case, and every host predating
// migration 028 is in it. The column defaults to "[]", which must read back as
// an empty list rather than failing the scan.
func TestHost_UnsafeNetworksDefaultsEmpty(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNetworkForUnsafe(t, s)

	host := &models.Host{
		ID: "h-plain", NetworkID: "n-1", Name: "plain",
		NebulaIPs: []string{"172.31.16.59"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	stored, err := s.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.UnsafeNetworks) != 0 {
		t.Errorf("unsafe networks = %v, want none", stored.UnsafeNetworks)
	}
}

func TestHost_UnsafeNetworksUpdate(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNetworkForUnsafe(t, s)

	host := &models.Host{
		ID: "h-gw", NetworkID: "n-1", Name: "gw",
		NebulaIPs: []string{"172.31.16.250"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	host.UnsafeNetworks = []string{"192.168.1.0/24"}
	if err := s.UpdateHost(ctx, host); err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}

	stored, err := s.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.UnsafeNetworks) != 1 || stored.UnsafeNetworks[0] != "192.168.1.0/24" {
		t.Fatalf("unsafe networks = %v, want [192.168.1.0/24]", stored.UnsafeNetworks)
	}

	// And clearing it must persist as "advertises nothing", not as a no-op.
	host.UnsafeNetworks = nil
	if err := s.UpdateHost(ctx, host); err != nil {
		t.Fatalf("UpdateHost clearing: %v", err)
	}
	stored, err = s.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.UnsafeNetworks) != 0 {
		t.Errorf("unsafe networks = %v after clearing, want none", stored.UnsafeNetworks)
	}
}

// ListHosts uses the same column list as GetHost; a mismatch between the two
// scan paths would surface as a scan error or silently empty field.
func TestHost_UnsafeNetworksVisibleInList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedNetworkForUnsafe(t, s)

	host := &models.Host{
		ID: "h-gw", NetworkID: "n-1", Name: "gw",
		NebulaIPs:      []string{"172.31.16.250"},
		UnsafeNetworks: []string{"192.168.1.0/24"},
		Role:           models.HostRoleHost,
		Status:         models.HostStatusEnrolled,
		CreatedAt:      time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	hosts, err := s.ListHosts(ctx, HostFilter{NetworkID: "n-1"})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if len(hosts[0].UnsafeNetworks) != 1 || hosts[0].UnsafeNetworks[0] != "192.168.1.0/24" {
		t.Errorf("unsafe networks = %v, want [192.168.1.0/24]", hosts[0].UnsafeNetworks)
	}
}

// The mesh-import write paths are separate from CreateHost/UpdateHost, so a
// column added to the latter silently drops out of the former. That is not
// cosmetic here: an imported gateway would enroll, then lose its routing
// authority at the next re-issuance and blackhole the LAN behind it.
func TestMeshImport_PersistsUnsafeNetworks(t *testing.T) {
	expected := 1
	s, session, now := newMeshImportFixture(t, &expected)
	imported := registerMeshImportTestHost(t, s, session, "gw", "10.42.0.10", now)

	// RegisterImportedHost is the INSERT path.
	stored, err := s.GetHost(context.Background(), imported.Host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.UnsafeNetworks) != 0 {
		t.Fatalf("registered host unsafe networks = %v, want none", stored.UnsafeNetworks)
	}

	// FinalizeMeshImport is the UPDATE path, and the one carrying the
	// reconciler's proposal.
	imported.Host.UnsafeNetworks = []string{"192.168.1.0/24"}
	if err := s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
		ID: session.ID, Revision: 1, Hosts: []MeshImportFinalizeHost{imported},
		FirewallJSON: `{"inbound":[],"outbound":[]}`, Now: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("finalize mesh import: %v", err)
	}

	stored, err = s.GetHost(context.Background(), imported.Host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.UnsafeNetworks) != 1 || stored.UnsafeNetworks[0] != "192.168.1.0/24" {
		t.Errorf("finalized host unsafe networks = %v, want [192.168.1.0/24]", stored.UnsafeNetworks)
	}
}
