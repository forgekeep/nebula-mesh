// Package configinput bridges domain hosts onto the config renderer's input.
//
// internal/configgen deliberately mirrors the few domain types it needs
// (configgen.FirewallRule, configgen.AdvancedUnsafeRoute) rather than importing
// internal/models, so that GeneratorInput stays an explicit render contract
// instead of a view onto the domain model. The cost of that boundary is that
// every caller building a GeneratorInput has to translate models.HostAdvanced
// field by field — and each new advanced field then has to be wired into every
// caller identically or it is silently dropped from one of them.
//
// This package holds that translation once. It is the only place that knows how
// a host's advanced overrides map onto the renderer, so adding an advanced
// field is a single edit.
package configinput

import (
	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

// ApplyHostAdvanced copies a host's advanced overrides onto input.
//
// A nil adv leaves input untouched, so a host with no advanced block renders
// byte-identically to before. Slice-valued overrides are appended, not
// assigned: HostFirewallInbound is additive on top of the network-wide policy
// the caller has already put in FirewallInbound.
func ApplyHostAdvanced(input *configgen.GeneratorInput, adv *models.HostAdvanced) {
	if input == nil || adv == nil {
		return
	}
	input.PunchyOverride = adv.Punchy
	input.ListenHost = adv.ListenHost
	input.MTU = adv.MTU
	input.TunDevice = adv.TunDevice
	for _, u := range adv.UnsafeRoutes {
		input.UnsafeRoutes = append(input.UnsafeRoutes, configgen.AdvancedUnsafeRoute{Route: u.Route, Via: u.Via})
	}
	for _, fr := range adv.FirewallInbound {
		input.HostFirewallInbound = append(input.HostFirewallInbound, configgen.FirewallRule{
			Port:      fr.Port,
			Proto:     fr.Proto,
			Group:     fr.Group,
			Cidr:      fr.Cidr,
			LocalCidr: fr.LocalCidr,
		})
	}
}
