package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// newDupNameHost builds a host fixture that differs from its sibling only in
// id and overlay address, so the sole constraint a second insert can trip is
// UNIQUE(network_id, name).
func newDupNameHost(networkID, id, name, ip string) *models.Host {
	return &models.Host{
		ID:        id,
		NetworkID: networkID,
		Name:      name,
		NebulaIPs: []string{ip},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		Groups:    []string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// TestCreateHostAndToken_DuplicateNameIsDuplicateEntry pins the agent-create
// path. A second host reusing a name already taken in the same network is an
// operator input error, not a server fault, so the store must report it as
// ErrDuplicateEntry — the sentinel the transports already translate into a
// friendly 400/409 — instead of leaking the raw SQLite constraint text and
// leaving handlers no choice but a generic 500.
func TestCreateHostAndToken_DuplicateNameIsDuplicateEntry(t *testing.T) {
	s := newTestStore(t)
	n := createTestNetwork(t, s)
	ctx := context.Background()

	tok := func(id, hostID string) *models.EnrollmentToken {
		return &models.EnrollmentToken{
			ID: id, HostID: hostID,
			ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
		}
	}

	if err := s.CreateHostAndToken(ctx, newDupNameHost(n.ID, "h1", "blai", "192.168.100.10"), tok("t1", "h1"), "raw-token-1"); err != nil {
		t.Fatalf("first create: %v", err)
	}

	err := s.CreateHostAndToken(ctx, newDupNameHost(n.ID, "h2", "blai", "192.168.100.11"), tok("t2", "h2"), "raw-token-2")
	if err == nil {
		t.Fatal("second create with a duplicate name succeeded; want an error")
	}
	if !errors.Is(err, ErrDuplicateEntry) {
		t.Errorf("errors.Is(err, ErrDuplicateEntry) = false, want true; got %v", err)
	}
}

// TestCreateHost_DuplicateNameIsDuplicateEntry pins the mobile-create path,
// which bypasses CreateHostAndToken and so needs the same mapping.
func TestCreateHost_DuplicateNameIsDuplicateEntry(t *testing.T) {
	s := newTestStore(t)
	n := createTestNetwork(t, s)
	ctx := context.Background()

	if err := s.CreateHost(ctx, newDupNameHost(n.ID, "m1", "movil", "192.168.100.20")); err != nil {
		t.Fatalf("first create: %v", err)
	}

	err := s.CreateHost(ctx, newDupNameHost(n.ID, "m2", "movil", "192.168.100.21"))
	if err == nil {
		t.Fatal("second create with a duplicate name succeeded; want an error")
	}
	if !errors.Is(err, ErrDuplicateEntry) {
		t.Errorf("errors.Is(err, ErrDuplicateEntry) = false, want true; got %v", err)
	}
}

// TestCreateHost_SameNameDifferentNetworkAllowed guards the blast radius: the
// constraint is per network, so the mapping must not turn a legitimate insert
// into a duplicate error.
func TestCreateHost_SameNameDifferentNetworkAllowed(t *testing.T) {
	s := newTestStore(t)
	n1 := createTestNetwork(t, s)
	ctx := context.Background()

	n2 := &models.Network{ID: "net_test2", Name: "second", CIDRs: []string{"192.168.200.0/24"}, CreatedAt: time.Now()}
	if err := s.CreateNetwork(ctx, n2); err != nil {
		t.Fatal(err)
	}

	if err := s.CreateHost(ctx, newDupNameHost(n1.ID, "a1", "shared", "192.168.100.30")); err != nil {
		t.Fatalf("create in first network: %v", err)
	}
	if err := s.CreateHost(ctx, newDupNameHost(n2.ID, "a2", "shared", "192.168.200.30")); err != nil {
		t.Errorf("same name in a different network must be allowed; got %v", err)
	}
}

// TestUpdateHost_DuplicateNameIsDuplicateEntry covers the rename half of the
// same constraint. Renaming a host onto a name another host already holds in
// the network trips UNIQUE(network_id, name) exactly like an insert does, so
// it must reach callers as the same sentinel rather than a raw SQLite error
// they can only report as a 500.
func TestUpdateHost_DuplicateNameIsDuplicateEntry(t *testing.T) {
	s := newTestStore(t)
	n := createTestNetwork(t, s)
	ctx := context.Background()

	if err := s.CreateHost(ctx, newDupNameHost(n.ID, "keep", "tauro", "192.168.100.40")); err != nil {
		t.Fatalf("create first: %v", err)
	}
	if err := s.CreateHost(ctx, newDupNameHost(n.ID, "move", "agricer", "192.168.100.41")); err != nil {
		t.Fatalf("create second: %v", err)
	}

	renamed := newDupNameHost(n.ID, "move", "tauro", "192.168.100.41")
	err := s.UpdateHost(ctx, renamed)
	if err == nil {
		t.Fatal("rename onto a taken name succeeded; want an error")
	}
	if !errors.Is(err, ErrDuplicateEntry) {
		t.Errorf("errors.Is(err, ErrDuplicateEntry) = false, want true; got %v", err)
	}
}

// TestUpdateHost_RenameToOwnNameSucceeds guards the exclusion rule: a host
// keeping its own name across an edit is not a collision with itself.
func TestUpdateHost_RenameToOwnNameSucceeds(t *testing.T) {
	s := newTestStore(t)
	n := createTestNetwork(t, s)
	ctx := context.Background()

	if err := s.CreateHost(ctx, newDupNameHost(n.ID, "self", "isis", "192.168.100.50")); err != nil {
		t.Fatalf("create: %v", err)
	}

	same := newDupNameHost(n.ID, "self", "isis", "192.168.100.50")
	same.Groups = []string{"edited"}
	if err := s.UpdateHost(ctx, same); err != nil {
		t.Errorf("keeping its own name must not be a conflict; got %v", err)
	}
}

// TestGetHostByName_ScopedToNetwork pins the lookup the transports use for
// their friendly pre-check: it resolves within a network and reports
// ErrNotFound rather than matching a same-named host in another network.
func TestGetHostByName_ScopedToNetwork(t *testing.T) {
	s := newTestStore(t)
	n1 := createTestNetwork(t, s)
	ctx := context.Background()

	n2 := &models.Network{ID: "net_other", Name: "other", CIDRs: []string{"192.168.200.0/24"}, CreatedAt: time.Now()}
	if err := s.CreateNetwork(ctx, n2); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHost(ctx, newDupNameHost(n1.ID, "lookup", "zeus", "192.168.100.60")); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetHostByName(ctx, n1.ID, "zeus")
	if err != nil {
		t.Fatalf("GetHostByName in owning network: %v", err)
	}
	if got.ID != "lookup" {
		t.Errorf("id = %q, want %q", got.ID, "lookup")
	}
	if len(got.NebulaIPs) != 1 || got.NebulaIPs[0] != "192.168.100.60" {
		t.Errorf("NebulaIPs = %v, want [192.168.100.60]", got.NebulaIPs)
	}

	if _, err := s.GetHostByName(ctx, n2.ID, "zeus"); !errors.Is(err, ErrNotFound) {
		t.Errorf("lookup in another network: err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetHostByName(ctx, n1.ID, "nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("lookup of a missing name: err = %v, want ErrNotFound", err)
	}
}
