package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// enrollLighthouse persists a lighthouse host directly in the store so peer
// configs can find it via getLighthouses. Bypasses the HTTP enrollment flow
// to keep this unit test small.
func enrollLighthouse(t *testing.T, srv *Server, networkID, hostID, name, nebulaIP, publicIP, fp string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	h := &models.Host{
		ID: hostID, NetworkID: networkID, Name: name,
		NebulaIPs: []string{nebulaIP}, Groups: []string{},
		Role: models.HostRoleLighthouse, IsLighthouse: true,
		PublicIP: publicIP, ListenPort: 4242,
		Status:          models.HostStatusEnrolled,
		CertFingerprint: fp,
		CreatedAt:       now, UpdatedAt: now,
	}
	if err := srv.store.CreateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := srv.store.UpdateHost(ctx, h); err != nil {
		t.Fatal(err)
	}
}

func TestGetLighthouses_ExcludesPending(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	// Lighthouse 1 — enrolled
	enrollLighthouse(t, srv, netID, "lh1", "lh-enrolled", "192.168.100.5", "1.2.3.4", "fp-lh1")

	// Lighthouse 2 — pending (not yet enrolled)
	pending := &models.Host{
		ID: "lh2", NetworkID: netID, Name: "lh-pending",
		NebulaIPs: []string{"192.168.100.6"}, Groups: []string{},
		Role: models.HostRoleLighthouse, IsLighthouse: true,
		PublicIP: "5.6.7.8", ListenPort: 4242,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := srv.store.CreateHost(ctx, pending); err != nil {
		t.Fatal(err)
	}

	lhs, err := srv.getLighthouses(ctx, netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(lhs) != 1 {
		t.Fatalf("got %d lighthouses, want 1 (pending must be excluded): %+v", len(lhs), lhs)
	}
	if len(lhs[0].NebulaIPs) == 0 || lhs[0].NebulaIPs[0] != "192.168.100.5" {
		t.Errorf("nebula_ips = %v, want [192.168.100.5]", lhs[0].NebulaIPs)
	}
	if lhs[0].PublicAddr != "1.2.3.4:4242" {
		t.Errorf("public_addr = %q, want 1.2.3.4:4242", lhs[0].PublicAddr)
	}
}

func TestGetLighthouses_ExcludesBlocked(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	enrollLighthouse(t, srv, netID, "lh1", "lh-keep", "192.168.100.5", "1.2.3.4", "fp-keep")
	enrollLighthouse(t, srv, netID, "lh2", "lh-block", "192.168.100.6", "5.6.7.8", "fp-block")

	if _, err := st.BlockHostAndAddToBlocklist(ctx, "lh2", "test"); err != nil {
		t.Fatal(err)
	}

	lhs, err := srv.getLighthouses(ctx, netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(lhs) != 1 {
		t.Fatalf("got %d lighthouses, want 1 (blocked must be excluded): %+v", len(lhs), lhs)
	}
	if len(lhs[0].NebulaIPs) == 0 || lhs[0].NebulaIPs[0] != "192.168.100.5" {
		t.Errorf("kept = %v, want [192.168.100.5]", lhs[0].NebulaIPs)
	}
}

func TestGetLighthouses_ZeroLighthouses(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	lhs, err := srv.getLighthouses(ctx, netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(lhs) != 0 {
		t.Errorf("got %d lighthouses, want 0", len(lhs))
	}
	if lhs == nil {
		t.Error("getLighthouses returned nil, want empty slice")
	}
}

func TestGetLighthouses_MultipleEnrolled(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	enrollLighthouse(t, srv, netID, "lh1", "lh-a", "192.168.100.5", "1.2.3.4", "fp-a")
	enrollLighthouse(t, srv, netID, "lh2", "lh-b", "192.168.100.6", "5.6.7.8", "fp-b")

	lhs, err := srv.getLighthouses(ctx, netID)
	if err != nil {
		t.Fatal(err)
	}
	if len(lhs) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(lhs), lhs)
	}
}

func TestRenderHostConfig_EmitsAllEnrolledLighthouses(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	enrollLighthouse(t, srv, netID, "lh1", "lh-a", "192.168.100.5", "1.2.3.4", "fp-a")
	enrollLighthouse(t, srv, netID, "lh2", "lh-b", "192.168.100.6", "5.6.7.8", "fp-b")

	host := &models.Host{
		ID: "host_peer", NetworkID: netID, Name: "peer",
		NebulaIPs: []string{"192.168.100.10"}, Groups: []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := srv.store.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	out := string(cfg)
	for _, expected := range []string{"192.168.100.5", "192.168.100.6", "1.2.3.4:4242", "5.6.7.8:4242"} {
		if !strings.Contains(out, expected) {
			t.Errorf("rendered config missing %q\n%s", expected, out)
		}
	}
	if !strings.Contains(out, "am_lighthouse: false") {
		t.Errorf("peer config should have am_lighthouse: false\n%s", out)
	}
}

// Task 2.4 tests: renderHostConfig with multi-address + family-match validation

func TestRenderHostConfig_PassesAllAddresses(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	enrollLighthouse(t, srv, netID, "lh1", "lighthouse", "192.168.100.1", "1.2.3.4", "fp-lh")

	host := &models.Host{
		ID: "host_multi", NetworkID: netID, Name: "multi-ip",
		NebulaIPs: []string{"192.168.100.10", "fd00::10"}, Groups: []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := srv.store.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatalf("renderHostConfig: %v", err)
	}

	// Config should be valid YAML and contain lighthouse information
	if len(cfg) == 0 {
		t.Error("rendered config should not be empty")
	}

	out := string(cfg)
	if !strings.Contains(out, "static_host_map") {
		t.Error("rendered config should contain static_host_map for lighthouse addresses")
	}
	if !strings.Contains(out, "192.168.100.1") {
		t.Error("rendered config should contain lighthouse address")
	}
}

func TestRenderHostConfig_UnsafeRouteFamilyMatch_Pass(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	enrollLighthouse(t, srv, netID, "lh1", "lighthouse", "192.168.100.1", "1.2.3.4", "fp-lh")

	host := &models.Host{
		ID: "host_dual", NetworkID: netID, Name: "dual-stack",
		NebulaIPs: []string{"192.168.100.10", "fd00::10"}, Groups: []string{},
		Role:   models.HostRoleHost,
		Status: models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			UnsafeRoutes: []models.UnsafeRoute{
				{Route: "10.99.0.0/24", Via: "192.168.100.2"}, // IPv4 to IPv4
				{Route: "fd00:99::/64", Via: "fd00::2"},       // IPv6 to IPv6
			},
		},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := srv.store.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatalf("renderHostConfig with matching families should succeed: %v", err)
	}

	// Should render without error
	if len(cfg) == 0 {
		t.Error("config should not be empty")
	}
}

func TestRenderHostConfig_UnsafeRouteFamilyMismatch(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	enrollLighthouse(t, srv, netID, "lh1", "lighthouse", "192.168.100.1", "1.2.3.4", "fp-lh")

	// Host has only IPv4, but unsafe_route tries IPv6 via
	host := &models.Host{
		ID: "host_ipv4_only", NetworkID: netID, Name: "ipv4-only",
		NebulaIPs: []string{"192.168.100.10"}, Groups: []string{},
		Role:   models.HostRoleHost,
		Status: models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			UnsafeRoutes: []models.UnsafeRoute{
				{Route: "fd00:99::/64", Via: "fd00::1"}, // IPv6 route but no IPv6 host address
			},
		},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := srv.store.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	cfg, err := srv.renderHostConfig(ctx, host)
	if err == nil {
		t.Fatal("renderHostConfig should fail when route family doesn't match host addresses")
		return
	}
	if cfg != nil {
		t.Error("config should be nil on error")
	}
	if !strings.Contains(err.Error(), "family") && !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error should mention family mismatch, got: %v", err)
	}
}
