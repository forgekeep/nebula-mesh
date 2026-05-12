package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
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
		NebulaIP: nebulaIP, Groups: []string{},
		Role: models.HostRoleLighthouse, IsLighthouse: true,
		PublicIP: publicIP, ListenPort: 4242,
		Status:    models.HostStatusEnrolled,
		CertFingerprint: fp,
		CreatedAt: now, UpdatedAt: now,
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
		NebulaIP: "192.168.100.6", Groups: []string{},
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
	if lhs[0].NebulaIP != "192.168.100.5" {
		t.Errorf("nebula_ip = %q, want 192.168.100.5", lhs[0].NebulaIP)
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
	if lhs[0].NebulaIP != "192.168.100.5" {
		t.Errorf("kept = %q, want 192.168.100.5", lhs[0].NebulaIP)
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
		NebulaIP: "192.168.100.10", Groups: []string{},
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
