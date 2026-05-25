package store

import (
	"context"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestListHosts_CAIDsScopeBeforeLimit pins that the CAIDs filter is applied in
// SQL before the LIMIT. Without it, a global "ORDER BY name LIMIT N" can fill
// the window with hosts under CAs the caller does not own, dropping the
// caller's own hosts — the undercount handleListHosts previously had when it
// filtered to owned CAs in Go after the limit.
func TestListHosts_CAIDsScopeBeforeLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s) // satisfies the host network_id FK

	mk := func(id, name, caID string) {
		if err := s.CreateHost(ctx, &models.Host{
			ID: id, NetworkID: net.ID, CAID: caID, Name: name,
			Role: models.HostRoleHost, Status: models.HostStatusPending,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}); err != nil {
			t.Fatalf("CreateHost %s: %v", name, err)
		}
	}
	// hosts.ca_id has no foreign key (migration 009), so these fabricated CA
	// ids need no cas rows — the scope filter keys on the column value alone.
	mk("h-foreign", "aaa-foreign", "ca-foreign") // sorts first by name
	mk("h-mine", "zzz-mine", "ca-mine")          // sorts last by name

	// Limit 1 with the foreign host sorting first: an unscoped query returns
	// only "aaa-foreign". The CAIDs scope must select "zzz-mine" instead.
	got, err := s.ListHosts(ctx, HostFilter{Limit: 1, CAIDs: []string{"ca-mine"}})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d hosts, want 1 (CAIDs scope must apply before LIMIT)", len(got))
	}
	if got[0].ID != "h-mine" {
		t.Errorf("got host %q, want h-mine", got[0].ID)
	}
}
