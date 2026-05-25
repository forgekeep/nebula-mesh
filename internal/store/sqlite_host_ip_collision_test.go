package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// hostWithIP builds a pending host carrying a single overlay address.
func hostWithIP(id, networkID, name, ip string) *models.Host {
	now := time.Now()
	return &models.Host{
		ID: id, NetworkID: networkID, Name: name,
		NebulaIPs: []string{ip}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
}

// TestCreateHost_DuplicateNebulaIP_Rejected locks the network-scoped overlay-IP
// invariant that migration 001 guaranteed via UNIQUE(network_id, nebula_ip) and
// migration 014 silently dropped: two distinct hosts in one network cannot hold
// the same address. Before the migration-018 + ON CONFLICT guard this passed
// silently (both inserts succeeded).
func TestCreateHost_DuplicateNebulaIP_Rejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	if err := s.CreateHost(ctx, hostWithIP("h1", net.ID, "host-1", "192.168.100.10")); err != nil {
		t.Fatalf("first create: %v", err)
	}

	err := s.CreateHost(ctx, hostWithIP("h2", net.ID, "host-2", "192.168.100.10"))
	if !errors.Is(err, ErrIPTaken) {
		t.Fatalf("second create err = %v, want ErrIPTaken", err)
	}

	// The losing create must roll back whole — no orphan host row.
	if _, err := s.GetHost(ctx, "h2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("losing host h2 should not exist; GetHost err = %v, want ErrNotFound", err)
	}
}

// TestCreateHost_ConcurrentSameNebulaIP_ExactlyOneWins fires N concurrent creates
// for distinct host names sharing one overlay IP and asserts exactly one wins
// while the rest get ErrIPTaken — the TOCTOU window validateHostIPs alone could
// not close. Mirrors TestPopNonces_ConcurrentSameNonceExactlyOneAccepted; run
// with -race.
func TestCreateHost_ConcurrentSameNebulaIP_ExactlyOneWins(t *testing.T) {
	// File-backed so the connection pool grows past one — :memory: forces
	// SetMaxOpenConns(1), serializing goroutines and masking the very race this
	// guards (see TestConsumeToken_AtomicUnderConcurrency for the rationale).
	dbPath := filepath.Join(t.TempDir(), "ip.db")
	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	net := createTestNetwork(t, s)

	const n = 8
	var wg sync.WaitGroup
	var wins, taken atomic.Int64
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h := hostWithIP(fmt.Sprintf("h%d", i), net.ID, fmt.Sprintf("host-%d", i), "192.168.100.20")
			<-start
			switch err := s.CreateHost(ctx, h); {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrIPTaken):
				taken.Add(1)
			case strings.Contains(err.Error(), "database is locked"):
				// SQLITE_BUSY under contention — a valid loss; the single-winner
				// invariant is pinned by wins==1 below.
				taken.Add(1)
			default:
				t.Errorf("goroutine %d: unexpected err %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got := wins.Load(); got != 1 {
		t.Errorf("winners = %d, want exactly 1", got)
	}
	if got := taken.Load(); got != n-1 {
		t.Errorf("ErrIPTaken = %d, want %d", got, n-1)
	}
}

// TestCreateHost_SameNebulaIP_DifferentNetworks_Allowed proves the guard is
// network-scoped, not global: distinct networks are independent address spaces.
func TestCreateHost_SameNebulaIP_DifferentNetworks_Allowed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	netA := createTestNetwork(t, s)
	netB := &models.Network{
		ID: "net_test2", Name: "test-network-2",
		CIDRs: []string{"192.168.100.0/24"}, CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, netB); err != nil {
		t.Fatalf("create netB: %v", err)
	}

	if err := s.CreateHost(ctx, hostWithIP("ha", netA.ID, "host-a", "192.168.100.30")); err != nil {
		t.Fatalf("create in netA: %v", err)
	}
	if err := s.CreateHost(ctx, hostWithIP("hb", netB.ID, "host-b", "192.168.100.30")); err != nil {
		t.Fatalf("same IP in a different network must be allowed: %v", err)
	}
}
