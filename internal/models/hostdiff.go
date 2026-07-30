package models

import (
	"encoding/json"
	"slices"
	"sort"
)

// HostDiff computes the difference between two hosts and returns a JSON-encoded
// map of changed fields. Returns (nil, false, nil) if no fields differ.
//
// For basic fields (Name, NebulaIPs, Groups, UnsafeNetworks, Role, PublicIP,
// ListenPort), the diff key is the field name in snake_case.
//
// For Advanced sub-fields (ListenHost, MTU, TunDevice, Punchy, UnsafeRoutes),
// the diff key uses dot-notation: "advanced.mtu", "advanced.punchy", etc.
//
// The JSON format for each changed field is:
// {"field_name": {"before": <value>, "after": <value>}}
//
// If before is nil, zero values are used. If before.Advanced is nil,
// zero values are used for sub-field comparisons.
func HostDiff(before, after *Host) ([]byte, bool, error) {
	if before == nil {
		before = &Host{}
	}
	if after == nil {
		after = &Host{}
	}

	// Build a map of changes
	changes := make(map[string]map[string]any)

	// Compare basic fields
	if before.Name != after.Name {
		changes["name"] = map[string]any{
			"before": before.Name,
			"after":  after.Name,
		}
	}

	if !slices.Equal(before.NebulaIPs, after.NebulaIPs) {
		changes["nebula_ips"] = map[string]any{
			"before": before.NebulaIPs,
			"after":  after.NebulaIPs,
		}
	}

	if !slices.Equal(before.Groups, after.Groups) {
		changes["groups"] = map[string]any{
			"before": before.Groups,
			"after":  after.Groups,
		}
	}

	if !slices.Equal(before.UnsafeNetworks, after.UnsafeNetworks) {
		changes["unsafe_networks"] = map[string]any{
			"before": before.UnsafeNetworks,
			"after":  after.UnsafeNetworks,
		}
	}

	if before.Role != after.Role {
		changes["role"] = map[string]any{
			"before": before.Role,
			"after":  after.Role,
		}
	}

	if before.PublicIP != after.PublicIP {
		changes["public_ip"] = map[string]any{
			"before": before.PublicIP,
			"after":  after.PublicIP,
		}
	}

	if before.ListenPort != after.ListenPort {
		changes["listen_port"] = map[string]any{
			"before": before.ListenPort,
			"after":  after.ListenPort,
		}
	}

	// Compare Advanced sub-fields
	beforeAdv := before.Advanced
	afterAdv := after.Advanced
	if beforeAdv == nil {
		beforeAdv = &HostAdvanced{}
	}
	if afterAdv == nil {
		afterAdv = &HostAdvanced{}
	}

	// MTU
	if beforeAdv.MTU != afterAdv.MTU {
		changes["advanced.mtu"] = map[string]any{
			"before": beforeAdv.MTU,
			"after":  afterAdv.MTU,
		}
	}

	// ListenHost
	if beforeAdv.ListenHost != afterAdv.ListenHost {
		changes["advanced.listen_host"] = map[string]any{
			"before": beforeAdv.ListenHost,
			"after":  afterAdv.ListenHost,
		}
	}

	// TunDevice
	if beforeAdv.TunDevice != afterAdv.TunDevice {
		changes["advanced.tun_device"] = map[string]any{
			"before": beforeAdv.TunDevice,
			"after":  afterAdv.TunDevice,
		}
	}

	// Punchy (tri-state)
	if !punchyEqual(beforeAdv.Punchy, afterAdv.Punchy) {
		changes["advanced.punchy"] = map[string]any{
			"before": beforeAdv.Punchy,
			"after":  afterAdv.Punchy,
		}
	}

	// UnsafeRoutes
	if !unsafeRoutesEqual(beforeAdv.UnsafeRoutes, afterAdv.UnsafeRoutes) {
		changes["advanced.unsafe_routes"] = map[string]any{
			"before": beforeAdv.UnsafeRoutes,
			"after":  afterAdv.UnsafeRoutes,
		}
	}

	// FirewallInbound
	if !hostFirewallRulesEqual(beforeAdv.FirewallInbound, afterAdv.FirewallInbound) {
		changes["advanced.firewall_inbound"] = map[string]any{
			"before": beforeAdv.FirewallInbound,
			"after":  afterAdv.FirewallInbound,
		}
	}

	// If no changes, return nil
	if len(changes) == 0 {
		return nil, false, nil
	}

	// Sort keys alphabetically for deterministic output
	keys := make([]string, 0, len(changes))
	for k := range changes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build JSON in sorted order
	orderedChanges := make(map[string]map[string]any)
	for _, k := range keys {
		orderedChanges[k] = changes[k]
	}

	jsonBytes, err := json.Marshal(orderedChanges)
	if err != nil {
		return nil, false, err
	}

	return jsonBytes, true, nil
}

// CertificateIdentity is the subset of a Host that is carried inside its
// Nebula certificate.
//
// It is intentionally separate from Host so callers that sign a certificate
// can retain precisely the identity they signed without also retaining mutable
// lifecycle or configuration state.
type CertificateIdentity struct {
	Name           string
	NebulaIPs      []string
	Groups         []string
	UnsafeNetworks []string
}

// CertificateIdentityFromHost returns an independent snapshot of the fields
// that are carried in a Host's Nebula certificate. A nil Host is the zero
// identity, matching HostDiff's nil-host convention.
func CertificateIdentityFromHost(host *Host) CertificateIdentity {
	identity := certificateIdentityFields(host)
	identity.NebulaIPs = append([]string(nil), identity.NebulaIPs...)
	identity.Groups = append([]string(nil), identity.Groups...)
	identity.UnsafeNetworks = append([]string(nil), identity.UnsafeNetworks...)
	return identity
}

// Equal reports whether two certificate identities describe the same Nebula
// certificate subject. Empty and nil slices are equivalent, as they are when a
// Host is diffed after a store or JSON round trip.
func (identity CertificateIdentity) Equal(other CertificateIdentity) bool {
	return identity.Name == other.Name &&
		slices.Equal(identity.NebulaIPs, other.NebulaIPs) &&
		slices.Equal(identity.Groups, other.Groups) &&
		slices.Equal(identity.UnsafeNetworks, other.UnsafeNetworks)
}

func certificateIdentityFields(host *Host) CertificateIdentity {
	if host == nil {
		return CertificateIdentity{}
	}
	return CertificateIdentity{
		Name:           host.Name,
		NebulaIPs:      host.NebulaIPs,
		Groups:         host.Groups,
		UnsafeNetworks: host.UnsafeNetworks,
	}
}

// CertIdentityChanged reports whether an edit touched a field that is carried
// inside the host's Nebula certificate: Name, NebulaIPs, Groups or
// UnsafeNetworks.
//
// Those four are the host's identity as far as the mesh is concerned. Peers
// authorize each other on the certificate rather than on the management
// server's host row, and firewall rules select their counterparties by group,
// so editing any of them is inert until a new certificate is issued. Callers
// use this to schedule that re-issuance. Every other field (Role, PublicIP,
// ListenPort, Advanced) only shapes the rendered config, which the agent picks
// up on its next poll without a new certificate.
//
// Both host-edit paths — the API's PATCH handler and the web UI's form — must
// agree on this, hence one definition rather than a copy each. It deliberately
// reuses the same comparators as HostDiff above, so what the audit trail
// records as a change and what triggers a re-issuance cannot drift apart.
//
// A nil side is treated as the zero Host, matching HostDiff.
func CertIdentityChanged(before, after *Host) bool {
	return !certificateIdentityFields(before).Equal(certificateIdentityFields(after))
}

// punchyEqual compares two tri-state bool pointers.
func punchyEqual(a, b *bool) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

// unsafeRoutesEqual compares two UnsafeRoute slices.
func unsafeRoutesEqual(a, b []UnsafeRoute) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Route != b[i].Route || a[i].Via != b[i].Via {
			return false
		}
	}
	return true
}

// hostFirewallRulesEqual compares two HostFirewallRule slices (order matters,
// as it is preserved into the rendered config).
func hostFirewallRulesEqual(a, b []HostFirewallRule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
