package web

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// SEC-PERSIST-001: recording a block does not establish mesh enforcement.
func TestHostDetail_BlockDoesNotClaimPeerEnforcement(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, nil)
	ctx := context.Background()
	const recorded = "Block recorded on the management server. Enforcement by other Nebula peers is not verified."
	require.NotContains(t, getHostDetail(t, w, cookies, "h-1"), recorded)
	_, err := s.BlockHostAndAddToBlocklist(ctx, "h-1", "operator block")
	require.NoError(t, err)
	require.Contains(t, getHostDetail(t, w, cookies, "h-1"), recorded)
}

// SEC-PERSIST-001: differentiate an authenticated agent ACK from having no
// evidence of delivery, and never equate either with enforcement.
func TestHostDetail_ConfigDeliveryDoesNotClaimEnforcement(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, nil)
	ctx := context.Background()
	now := time.Now().UTC()
	const disclaimer = "This does not verify enforcement by Nebula."
	check := func(id, label string) {
		t.Helper()
		page := getHostDetail(t, w, cookies, id)
		if !strings.Contains(page, label) || !strings.Contains(page, disclaimer) {
			t.Fatalf("host %s: missing delivery label %q or enforcement disclaimer", id, label)
		}
		if label != "Current config acknowledged by agent." && strings.Contains(page, "Current config acknowledged by agent.") {
			t.Fatalf("host %s: delivery was incorrectly shown as acknowledged", id)
		}
	}

	// Marking a version current in the legacy path is not an ACK.
	version, err := s.GetNetworkConfigVersion(ctx, "n-1")
	require.NoError(t, err)
	require.NoError(t, s.UpdateHostConfigVersion(ctx, "h-1", version))
	require.NoError(t, s.UpdateHostLastSeen(ctx, "h-1", now))
	check("h-1", "No config acknowledgement support reported.")

	require.NoError(t, s.CreateHost(ctx, &models.Host{
		ID: "h-2", NetworkID: "n-1", Name: "managed-peer", NebulaIPs: []string{"192.168.100.11"},
		Role: models.HostRoleHost, Kind: models.HostKindAgent, Status: models.HostStatusPending, CreatedAt: now, UpdatedAt: now,
	}))
	require.NoError(t, s.CreateTokenForHost(ctx, "h-2", "fixture-token", now.Add(time.Hour)))
	dir := t.TempDir()
	profile := models.AgentProfile{
		NebulaConfigPath: filepath.Join(dir, "config.yml"),
		NebulaCAPath:     filepath.Join(dir, "ca.crt"),
		NebulaCertPath:   filepath.Join(dir, "host.crt"),
		NebulaKeyPath:    filepath.Join(dir, "host.key"),
		ConfigAckV1:      true,
	}
	pending, err := s.ConsumeTokenAndEnrollHostWithProfile(ctx, "h-2", "fixture-token", []byte("fixture-cert"),
		strings.Repeat("a", 64), now, now.Add(time.Hour), "fixture-public-signing-key", profile, nil)
	require.NoError(t, err)
	require.Positive(t, pending)
	require.NoError(t, s.UpdateHostLastSeen(ctx, "h-2", now))
	check("h-2", "Waiting for the agent to acknowledge the current config.")

	require.NoError(t, s.AcknowledgeHostConfigVersion(ctx, "h-2", pending))
	check("h-2", "Current config acknowledged by agent.")
	require.NoError(t, s.UpdateHostLastSeen(ctx, "h-2", now.Add(-time.Hour)))
	check("h-2", "No recent agent poll; current delivery is unverified.")
	require.NoError(t, s.UpdateHostLastSeen(ctx, "h-2", now))
	require.NoError(t, s.BumpNetworkConfigVersion(ctx, "n-1"))
	check("h-2", "Waiting for the agent to acknowledge the current config.")

	require.NoError(t, s.CreateHost(ctx, &models.Host{
		ID: "h-3", NetworkID: "n-1", Name: "static-mobile", NebulaIPs: []string{"192.168.100.12"},
		Role: models.HostRoleHost, Kind: models.HostKindMobile, Variant: models.HostVariantIOS,
		Status: models.HostStatusEnrolled, CreatedAt: now, UpdatedAt: now,
	}))
	check("h-3", "No agent acknowledgement for mobile bundles.")
}
