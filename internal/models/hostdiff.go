package models

import (
	"encoding/json"
	"sort"
)

// HostDiff computes the difference between two hosts and returns a JSON-encoded
// map of changed fields. Returns (nil, false, nil) if no fields differ.
//
// For basic fields (Name, NebulaIPs, Groups, Role, PublicIP, ListenPort),
// the diff key is the field name in snake_case.
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

	if !nebulIPsEqual(before.NebulaIPs, after.NebulaIPs) {
		changes["nebula_ips"] = map[string]any{
			"before": before.NebulaIPs,
			"after":  after.NebulaIPs,
		}
	}

	if !groupsEqual(before.Groups, after.Groups) {
		changes["groups"] = map[string]any{
			"before": before.Groups,
			"after":  after.Groups,
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

// nebulIPsEqual compares two IP slices for equality (order matters).
func nebulIPsEqual(a, b []string) bool {
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

// groupsEqual compares two string slices for equality (order matters).
func groupsEqual(a, b []string) bool {
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
