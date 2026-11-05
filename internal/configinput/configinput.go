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
	"sort"

	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
)

// HostRuntime is the Nebula release and OS config is rendered for: the
// agent's report, else the operator's advanced.nebula_version. Every caller
// building a GeneratorInput for a host sets input.Runtime from it.
func HostRuntime(host *models.Host) nebulacompat.Runtime {
	if host == nil {
		return nebulacompat.Runtime{}
	}
	var operator string
	if host.Advanced != nil {
		operator = host.Advanced.NebulaVersion
	}
	return nebulacompat.HostRuntime(host.NebulaVersion, host.NebulaOS, operator, host.Kind == models.HostKindMobile)
}

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
	input.PunchyRespondOverride = adv.PunchyRespond
	input.ListenHost = adv.ListenHost
	input.MTU = adv.MTU
	input.TunDevice = adv.TunDevice
	input.Routines = adv.Routines
	input.UDPOffloads = adv.UDPOffloads
	input.TunOffloads = adv.TunOffloads
	input.PinThreads = adv.PinThreads
	input.PinThreadsKey = adv.PinThreadsKey
	input.CPUAffinity = adv.CPUAffinity
	input.LocalAPIControlEnabled = adv.LocalAPIControlEnabled
	input.LocalAPIControlGroup = adv.LocalAPIControlGroup
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

// Lighthouses translates the lighthouses among hosts into the static
// endpoints every peer renders, keeping the order of hosts. The API's config
// rendering and the mobile bundle builder share it and Relays so agents and
// mobile clients are given the same topology.
func Lighthouses(hosts []*models.Host) []configgen.LighthouseInfo {
	result := make([]configgen.LighthouseInfo, 0)
	for _, h := range hosts {
		endpoints := h.LighthouseEndpoints()
		if len(endpoints) == 0 {
			continue
		}
		result = append(result, configgen.LighthouseInfo{
			NebulaIPs:  h.NebulaIPs,
			PublicAddr: endpoints[0],
			ExtraAddrs: endpoints[1:],
		})
	}
	return result
}

// Relays returns the sorted, de-duplicated overlay addresses of the relays
// among hosts, for relay.relays.
func Relays(hosts []*models.Host) []string {
	set := make(map[string]struct{})
	for _, host := range hosts {
		if !host.Role.Relay() && !host.IsRelay {
			continue
		}
		for _, address := range host.NebulaIPs {
			set[address] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for address := range set {
		result = append(result, address)
	}
	sort.Strings(result)
	return result
}
