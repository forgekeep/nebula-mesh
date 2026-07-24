package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestUpdateHost_ResetsConfigVersion: UpdateHost must reset the host's
// config_version to 0 inside its own transaction so agents re-render on the
// next poll. Relying on a separate best-effort write violates
// SEC-PERSIST-001: the durable Host state and the re-publish trigger must
// commit together.
func TestUpdateHost_ResetsConfigVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	h := &models.Host{
		ID: "host_cv", NetworkID: net.ID, Name: "cv", NebulaIPs: []string{"192.168.100.40"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	// Simulate an agent that already consumed config version 5.
	if err := s.UpdateHostConfigVersion(ctx, h.ID, 5); err != nil {
		t.Fatal(err)
	}

	h.Advanced = &models.HostAdvanced{
		FirewallInbound: []models.HostFirewallRule{{Port: "22", Proto: "tcp", Group: "admin"}},
	}
	if err := s.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}

	version, err := s.GetHostConfigVersion(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Errorf("config version after UpdateHost = %d, want 0 (SEC-PERSIST-001)", version)
	}
}

// TestUpdateHost_SECPERSIST001_RollbackIsAtomic is the negative regression
// for SEC-PERSIST-001: when the UpdateHost transaction fails, the firewall
// state (advanced_json) and the config_version reset must roll back
// together. Otherwise a removed inbound rule could be durably gone from the
// Host row while the agent keeps serving the old, more permissive config
// forever. The transaction failure is forced through the
// UNIQUE(network_id, address) guard in setHostAddresses.
func TestUpdateHost_SECPERSIST001_RollbackIsAtomic(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	net := createTestNetwork(t, s)

	victim := &models.Host{
		ID: "host_victim", NetworkID: net.ID, Name: "victim", NebulaIPs: []string{"192.168.100.41"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			FirewallInbound: []models.HostFirewallRule{{Port: "22", Proto: "tcp", Group: "admin"}},
		},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, victim); err != nil {
		t.Fatal(err)
	}
	other := &models.Host{
		ID: "host_other", NetworkID: net.ID, Name: "other", NebulaIPs: []string{"192.168.100.42"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateHostConfigVersion(ctx, victim.ID, 5); err != nil {
		t.Fatal(err)
	}

	// Attempt to remove the firewall rule while also claiming the other
	// host's address — the address collision must abort the whole tx.
	mutated := *victim
	mutated.Advanced = nil
	mutated.NebulaIPs = []string{"192.168.100.42"}
	err := s.UpdateHost(ctx, &mutated)
	if err == nil {
		t.Fatal("UpdateHost with colliding address should fail")
	}
	if !errors.Is(err, ErrIPTaken) {
		t.Fatalf("err = %v, want ErrIPTaken", err)
	}

	// Firewall state must be untouched…
	got, err := s.GetHost(ctx, victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Advanced == nil || len(got.Advanced.FirewallInbound) != 1 {
		t.Errorf("firewall rule lost after failed tx: %+v (SEC-PERSIST-001)", got.Advanced)
	}
	// …and the config version must NOT have been reset.
	version, err := s.GetHostConfigVersion(ctx, victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if version != 5 {
		t.Errorf("config version after failed tx = %d, want 5 (SEC-PERSIST-001)", version)
	}
}
