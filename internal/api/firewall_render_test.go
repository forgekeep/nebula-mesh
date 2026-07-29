package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// renderTestHost inserts a minimal enrolled host into netID and returns it.
func renderTestHost(t *testing.T, srv *Server, netID string) *models.Host {
	t.Helper()
	host := &models.Host{
		ID: "fw-host", NetworkID: netID, Name: "fw-peer",
		NebulaIPs: []string{"192.168.100.20"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := srv.store.CreateHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	return host
}

// TestRenderHostConfig_AppliesStoredFirewallRules is the M1 regression: a
// network's stored firewall policy must reach the generated agent config.
// Before the fix the renderer hardcoded icmp-inbound/allow-all-outbound and
// ignored getFirewallRules entirely, so an operator's policy was accepted and
// echoed by the API but never enforced. The distinctive group name cannot
// appear in the hardcoded default, so its presence proves the stored rule was
// rendered.
func TestRenderHostConfig_AppliesStoredFirewallRules(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	const policy = `{"inbound":[{"port":"443","proto":"tcp","group":"auditors-only"}],` +
		`"outbound":[{"port":"any","proto":"any","group":"any"}]}`
	if err := srv.store.SetNetworkConfig(ctx, netID, "firewall", policy); err != nil {
		t.Fatal(err)
	}

	host := renderTestHost(t, srv, netID)
	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	out := string(cfg)
	if !strings.Contains(out, "auditors-only") {
		t.Errorf("rendered config does not contain the stored firewall group; rules were not applied\n%s", out)
	}
	if !strings.Contains(out, `port: "443"`) {
		t.Errorf("rendered config does not contain the stored firewall port\n%s", out)
	}
}

// TestRenderHostConfig_DefaultFirewallWhenNoneStored pins that a network with
// no firewall policy keeps the safe baseline (icmp inbound), so the fix does
// not silently change behavior for networks that never configured rules.
func TestRenderHostConfig_DefaultFirewallWhenNoneStored(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	host := renderTestHost(t, srv, netID)
	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	out := string(cfg)
	if !strings.Contains(out, "icmp") {
		t.Errorf("rendered config missing the default icmp inbound rule\n%s", out)
	}
	if strings.Contains(out, "auditors-only") {
		t.Errorf("rendered config unexpectedly contains a custom group with no policy stored\n%s", out)
	}
}

// TestRenderHostConfig_UnusableFirewallFallsBackToDefault pins that a stored
// policy with an empty group (the work-322fy footgun, reachable via pre-#200
// data) does NOT render a config Nebula rejects: the renderer falls back to
// the safe baseline rather than emitting a rule with neither group nor host.
func TestRenderHostConfig_UnusableFirewallFallsBackToDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	const bad = `{"inbound":[{"port":"22","proto":"tcp","group":""}],"outbound":[]}`
	if err := srv.store.SetNetworkConfig(ctx, netID, "firewall", bad); err != nil {
		t.Fatal(err)
	}

	host := renderTestHost(t, srv, netID)
	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	out := string(cfg)
	// Fell back to the baseline (icmp inbound), and the broken rule's port is
	// not present (it would have rendered a group-less, host-less rule).
	if !strings.Contains(out, "icmp") {
		t.Errorf("expected fallback to default icmp baseline\n%s", out)
	}
	if strings.Contains(out, `port: "22"`) {
		t.Errorf("unusable rule was rendered instead of falling back\n%s", out)
	}
}

// TestRenderHostConfig_AppendsHostFirewallInbound: per-host inbound rules
// (advanced.firewall_inbound) must be rendered after the network-wide
// policy, additively — the network baseline must remain present.
func TestRenderHostConfig_AppendsHostFirewallInbound(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	const policy = `{"inbound":[{"port":"443","proto":"tcp","group":"auditors-only"}],` +
		`"outbound":[{"port":"any","proto":"any","group":"any"}]}`
	if err := srv.store.SetNetworkConfig(ctx, netID, "firewall", policy); err != nil {
		t.Fatal(err)
	}

	host := renderTestHost(t, srv, netID)
	host.Advanced = &models.HostAdvanced{
		FirewallInbound: []models.HostFirewallRule{
			{Port: "22", Proto: "tcp", Group: "bastion-admins"},
		},
	}

	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	out := string(cfg)
	if !strings.Contains(out, "auditors-only") {
		t.Errorf("network policy rule missing from rendered config\n%s", out)
	}
	if !strings.Contains(out, "bastion-admins") {
		t.Errorf("per-host firewall rule missing from rendered config\n%s", out)
	}
	if !strings.Contains(out, `port: "22"`) {
		t.Errorf("per-host firewall port missing from rendered config\n%s", out)
	}
	if netIdx, hostIdx := strings.Index(out, "auditors-only"), strings.Index(out, "bastion-admins"); netIdx > hostIdx {
		t.Errorf("network rule should render before the per-host rule\n%s", out)
	}
}

// TestRenderHostConfig_AppliesStoredCIDRRules is the end-to-end path for the
// cidr / local_cidr fields: a stored policy using them must reach the agent
// config as `cidr:` / `local_cidr:` keys, and a cidr-selected rule must not
// pick up a `host: any` on the way — Nebula OR's the peer selectors, so that
// would match every peer and discard the prefix restriction.
func TestRenderHostConfig_AppliesStoredCIDRRules(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	const policy = `{"inbound":[` +
		`{"port":"443","proto":"tcp","cidr":"10.77.0.0/24"},` +
		`{"port":"22","proto":"tcp","group":"admins-only","local_cidr":"192.0.2.0/24"}],` +
		`"outbound":[{"port":"any","proto":"any","group":"any"}]}`
	if err := srv.store.SetNetworkConfig(ctx, netID, "firewall", policy); err != nil {
		t.Fatal(err)
	}

	host := renderTestHost(t, srv, netID)
	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Firewall struct {
			Inbound []map[string]any `yaml:"inbound"`
		} `yaml:"firewall"`
	}
	if err := yaml.Unmarshal(cfg, &parsed); err != nil {
		t.Fatalf("rendered config is not valid YAML: %v\n%s", err, cfg)
	}
	in := parsed.Firewall.Inbound
	if len(in) != 2 {
		t.Fatalf("inbound rules = %d, want 2\n%s", len(in), cfg)
	}

	// The cidr-selected rule must carry the prefix and no host/group.
	if in[0]["cidr"] != "10.77.0.0/24" {
		t.Errorf("inbound[0].cidr = %v, want 10.77.0.0/24", in[0]["cidr"])
	}
	if _, ok := in[0]["host"]; ok {
		t.Errorf("cidr-selected rule gained host, widening it to every peer: %v", in[0])
	}
	if _, ok := in[0]["group"]; ok {
		t.Errorf("cidr-selected rule gained group: %v", in[0])
	}

	if in[1]["group"] != "admins-only" || in[1]["local_cidr"] != "192.0.2.0/24" {
		t.Errorf("inbound[1] = %v, want group admins-only with local_cidr 192.0.2.0/24", in[1])
	}
}

// TestRenderHostConfig_WiderCIDRRuleFallsBackToDefault pins that a stored rule
// carrying both a group and a cidr — which Nebula would OR into a wider rule —
// is refused at render time and the host receives the safe baseline instead.
func TestRenderHostConfig_WiderCIDRRuleFallsBackToDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	ctx := context.Background()

	const policy = `{"inbound":[{"port":"443","proto":"tcp","group":"web","cidr":"10.77.0.0/24"}],` +
		`"outbound":[{"port":"any","proto":"any","group":"any"}]}`
	if err := srv.store.SetNetworkConfig(ctx, netID, "firewall", policy); err != nil {
		t.Fatal(err)
	}

	host := renderTestHost(t, srv, netID)
	cfg, err := srv.renderHostConfig(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	out := string(cfg)
	if strings.Contains(out, "10.77.0.0/24") || strings.Contains(out, "group: web") {
		t.Errorf("rule with both group and cidr was rendered instead of falling back\n%s", out)
	}
	if !strings.Contains(out, "proto: icmp") {
		t.Errorf("expected the icmp baseline after fallback\n%s", out)
	}
}
