package store

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// seedEditableHost creates a network and one host ready to be edited.
func seedEditableHost(t *testing.T, s *SQLiteStore) *models.Host {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-1", Name: "net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	host := &models.Host{
		ID: "h-1", NetworkID: "n-1", Name: "web-1",
		NebulaIPs: []string{"10.0.0.1"},
		Groups:    []string{"web"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}
	return host
}

// TestApplyHostEdit_SchedulesRekeyForCertBoundFields: the whole point of the
// shared applier — an edit to a certificate-bound field must come back out of
// the store with the re-issuance scheduled.
func TestApplyHostEdit_SchedulesRekeyForCertBoundFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*models.Host)
	}{
		{"name", func(h *models.Host) { h.Name = "web-2" }},
		{"ips", func(h *models.Host) { h.NebulaIPs = []string{"10.0.0.9"} }},
		{"groups added", func(h *models.Host) { h.Groups = []string{"web", "admin"} }},
		{"groups removed", func(h *models.Host) { h.Groups = nil }},
		{"unsafe networks added", func(h *models.Host) { h.UnsafeNetworks = []string{"192.168.1.0/24"} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			ctx := context.Background()
			host := seedEditableHost(t, s)

			before := *host
			after := *host
			tt.mutate(&after)

			if err := ApplyHostEdit(ctx, s, quietLogger(), &before, &after); err != nil {
				t.Fatalf("ApplyHostEdit: %v", err)
			}

			// The flag has to be persisted, not just set on the struct — the
			// agent learns about the rekey from the host row on its next poll.
			stored, err := s.GetHost(ctx, host.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !stored.PendingRekey {
				t.Error("PendingRekey was not persisted")
			}
			if !after.PendingRekey {
				t.Error("PendingRekey was not reflected on the caller's host, which is what the API returns")
			}
		})
	}
}

// TestApplyHostEdit_NoRekeyForConfigOnlyFields pins the other direction:
// config-only edits must not churn certificates.
func TestApplyHostEdit_NoRekeyForConfigOnlyFields(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	host := seedEditableHost(t, s)

	before := *host
	after := *host
	after.PublicIP = "203.0.113.7"
	after.ListenPort = 4242

	if err := ApplyHostEdit(ctx, s, quietLogger(), &before, &after); err != nil {
		t.Fatalf("ApplyHostEdit: %v", err)
	}

	stored, err := s.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PendingRekey {
		t.Error("a config-only edit must not schedule a certificate re-issuance")
	}
	if stored.PublicIP != "203.0.113.7" {
		t.Errorf("PublicIP = %q, want the edited value", stored.PublicIP)
	}
}

// TestApplyHostEdit_RekeyCommitsWithTheHostRow is the reason the flag is set
// on the struct instead of through a second SetPendingRekey write: both land
// in UpdateHost's single transaction, so there is no window in which the new
// groups are persisted while the re-issuance that carries them is not.
func TestApplyHostEdit_RekeyCommitsWithTheHostRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	host := seedEditableHost(t, s)

	before := *host
	after := *host
	after.Groups = []string{"admin"}

	if err := ApplyHostEdit(ctx, s, quietLogger(), &before, &after); err != nil {
		t.Fatalf("ApplyHostEdit: %v", err)
	}

	stored, err := s.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.Groups; len(got) != 1 || got[0] != "admin" {
		t.Fatalf("Groups = %v, want [admin]", got)
	}
	if !stored.PendingRekey {
		t.Error("the new groups are visible but the re-issuance was not scheduled with them")
	}
	// SEC-PERSIST-001: the same transaction re-publishes the config.
	version, err := s.GetHostConfigVersion(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if version != 0 {
		t.Errorf("config_version = %d, want 0 (reset in the same commit)", version)
	}
}

// TestApplyHostEdit_Idempotent: re-applying an edit over an already-pending
// host must not error. The old SetPendingRekey path answered
// ErrRekeyAlreadyPending here and every caller had to special-case it.
func TestApplyHostEdit_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	host := seedEditableHost(t, s)

	before := *host
	after := *host
	after.Groups = []string{"admin"}

	for i := range 2 {
		if err := ApplyHostEdit(ctx, s, quietLogger(), &before, &after); err != nil {
			t.Fatalf("ApplyHostEdit call %d: %v", i+1, err)
		}
	}

	stored, err := s.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.PendingRekey {
		t.Error("PendingRekey should still be set after a repeated apply")
	}
}

// TestApplyHostEdit_RoleChangeBumpsNetworkVersion: a role change alters the
// topology every peer renders, so it has to re-publish network-wide.
func TestApplyHostEdit_RoleChangeBumpsNetworkVersion(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	host := seedEditableHost(t, s)

	initial, err := s.GetNetworkConfigVersion(ctx, "n-1")
	if err != nil {
		t.Fatal(err)
	}

	before := *host
	after := *host
	after.Role = models.HostRoleLighthouse
	after.IsLighthouse = true

	if err := ApplyHostEdit(ctx, s, quietLogger(), &before, &after); err != nil {
		t.Fatalf("ApplyHostEdit: %v", err)
	}

	bumped, err := s.GetNetworkConfigVersion(ctx, "n-1")
	if err != nil {
		t.Fatal(err)
	}
	if bumped <= initial {
		t.Errorf("network config version = %d, want greater than %d", bumped, initial)
	}
}

// TestApplyHostEdit_PropagatesStoreError: a failed persist must reach the
// caller so it can map the status, and must not be masked by the follow-up
// writes.
func TestApplyHostEdit_PropagatesStoreError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	missing := &models.Host{
		ID: "nope", NetworkID: "n-1", Name: "ghost",
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
	}
	before := *missing
	after := *missing
	after.Name = "ghost-2"

	err := ApplyHostEdit(ctx, s, quietLogger(), &before, &after)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}
