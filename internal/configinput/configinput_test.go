package configinput

import (
	"reflect"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestApplyHostAdvanced_CopiesEveryField is the guard that makes this package
// worth having: it fails when a field is added to models.HostAdvanced without
// being wired into ApplyHostAdvanced, which would otherwise silently drop the
// override from every rendered config.
func TestApplyHostAdvanced_CopiesEveryField(t *testing.T) {
	punchy := false
	punchyRespond := true
	adv := &models.HostAdvanced{
		Punchy:        &punchy,
		PunchyRespond: &punchyRespond,
		ListenHost:    "10.0.0.1",
		MTU:           1300,
		TunDevice:     "nebula1",
		UnsafeRoutes: []models.UnsafeRoute{
			{Route: "192.168.10.0/24", Via: "10.0.0.99"},
		},
		FirewallInbound: []models.HostFirewallRule{
			{Port: "22", Proto: "tcp", Group: "admin"},
			{Port: "443", Proto: "tcp", Cidr: "10.0.5.0/24"},
			{Port: "any", Proto: "any", Group: "gw", LocalCidr: "192.168.10.0/24"},
		},
	}

	var input configgen.GeneratorInput
	ApplyHostAdvanced(&input, adv)

	if input.PunchyOverride == nil || *input.PunchyOverride {
		t.Errorf("PunchyOverride = %v, want explicit false", input.PunchyOverride)
	}
	if input.PunchyRespondOverride == nil || !*input.PunchyRespondOverride {
		t.Errorf("PunchyRespondOverride = %v, want explicit true", input.PunchyRespondOverride)
	}
	if input.ListenHost != "10.0.0.1" || input.MTU != 1300 || input.TunDevice != "nebula1" {
		t.Errorf("scalar overrides not copied: %+v", input)
	}
	wantRoutes := []configgen.AdvancedUnsafeRoute{{Route: "192.168.10.0/24", Via: "10.0.0.99"}}
	if !reflect.DeepEqual(input.UnsafeRoutes, wantRoutes) {
		t.Errorf("UnsafeRoutes = %+v, want %+v", input.UnsafeRoutes, wantRoutes)
	}
	wantRules := []configgen.FirewallRule{
		{Port: "22", Proto: "tcp", Group: "admin"},
		{Port: "443", Proto: "tcp", Cidr: "10.0.5.0/24"},
		{Port: "any", Proto: "any", Group: "gw", LocalCidr: "192.168.10.0/24"},
	}
	if !reflect.DeepEqual(input.HostFirewallInbound, wantRules) {
		t.Errorf("HostFirewallInbound = %+v, want %+v", input.HostFirewallInbound, wantRules)
	}

	// Every exported field of HostAdvanced must be represented above, so that
	// adding one to the model breaks this test rather than silently rendering
	// nothing.
	const wantFields = 7
	if got := reflect.TypeOf(models.HostAdvanced{}).NumField(); got != wantFields {
		t.Errorf("models.HostAdvanced has %d fields, this test covers %d — wire the new field "+
			"into ApplyHostAdvanced and extend this test", got, wantFields)
	}
}

// TestApplyHostAdvanced_NilIsNoOp pins that a host with no advanced block
// renders exactly as it did before, and that a nil input cannot panic.
func TestApplyHostAdvanced_NilIsNoOp(t *testing.T) {
	input := configgen.GeneratorInput{HostName: "h", MTU: 1400}
	ApplyHostAdvanced(&input, nil)
	if input.MTU != 1400 || input.HostName != "h" {
		t.Errorf("nil adv modified input: %+v", input)
	}
	if input.UnsafeRoutes != nil || input.HostFirewallInbound != nil {
		t.Errorf("nil adv appended slices: %+v", input)
	}
	ApplyHostAdvanced(nil, &models.HostAdvanced{MTU: 1300}) // must not panic
}

// TestApplyHostAdvanced_AppendsRatherThanReplaces pins that per-host firewall
// rules land after the network-wide policy the caller already set.
func TestApplyHostAdvanced_AppendsRatherThanReplaces(t *testing.T) {
	input := configgen.GeneratorInput{
		FirewallInbound: []configgen.FirewallRule{{Port: "any", Proto: "icmp", Group: "any"}},
		HostFirewallInbound: []configgen.FirewallRule{
			{Port: "80", Proto: "tcp", Group: "web"},
		},
	}
	ApplyHostAdvanced(&input, &models.HostAdvanced{
		FirewallInbound: []models.HostFirewallRule{{Port: "22", Proto: "tcp", Group: "admin"}},
	})
	if len(input.FirewallInbound) != 1 {
		t.Errorf("network policy was modified: %+v", input.FirewallInbound)
	}
	if len(input.HostFirewallInbound) != 2 || input.HostFirewallInbound[1].Group != "admin" {
		t.Errorf("host rules should be appended in order: %+v", input.HostFirewallInbound)
	}
}
