package store

import (
	"context"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// blockedHostFixture creates an enrolled host under caID with the given cert
// fingerprint and adds it to the blocklist, returning nothing — the assertions
// run against the store.
func blockedHostFixture(t *testing.T, s *SQLiteStore, id, caID, fp, ip string) {
	t.Helper()
	ctx := context.Background()
	h := &models.Host{
		ID: id, NetworkID: "net_test1", Name: id, CAID: caID,
		NebulaIPs: []string{ip}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	h.CertFingerprint = fp
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BlockHostAndAddToBlocklist(ctx, h.ID, "test block"); err != nil {
		t.Fatal(err)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// TestGetBlocklistForCA_ScopesByCA verifies that the per-CA blocklist returned
// to a polling agent contains only its own CA's revoked fingerprints, not those
// of other operators' CAs — closing the cross-tenant disclosure where the poll
// handler shipped the global blocklist to every host (#203).
func TestGetBlocklistForCA_ScopesByCA(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	createTestNetwork(t, s)

	blockedHostFixture(t, s, "h-ca1", "ca-1", "fp-ca1", "192.168.100.21")
	blockedHostFixture(t, s, "h-ca2", "ca-2", "fp-ca2", "192.168.100.22")

	bl1, err := s.GetBlocklistForCA(ctx, "ca-1")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(bl1, "fp-ca1") {
		t.Errorf("CA-1 blocklist should contain its own fingerprint fp-ca1, got %v", bl1)
	}
	if contains(bl1, "fp-ca2") {
		t.Errorf("CA-1 blocklist leaks CA-2's fingerprint fp-ca2: %v", bl1)
	}

	bl2, err := s.GetBlocklistForCA(ctx, "ca-2")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(bl2, "fp-ca2") {
		t.Errorf("CA-2 blocklist should contain fp-ca2, got %v", bl2)
	}
	if contains(bl2, "fp-ca1") {
		t.Errorf("CA-2 blocklist leaks CA-1's fingerprint fp-ca1: %v", bl2)
	}

	// The admin/global view still sees everything.
	all, err := s.GetBlocklist(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(all, "fp-ca1") || !contains(all, "fp-ca2") {
		t.Errorf("global blocklist should contain both fingerprints, got %v", all)
	}
}
