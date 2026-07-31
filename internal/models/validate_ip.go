package models

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// tunDeviceRe is the strict whitelist for TunDevice (advanced.tun_device).
// Closes GHSA-7hp6-g3pq-3pc3: the previous denylist (whitespace + slash)
// missed carriage-return and Unicode line separators which YAML parsers
// accept as line terminators, enabling injection into the rendered agent
// config.yml. Linux caps interface names at IFNAMSIZ (15 printable bytes
// + NUL), so a 1-15 char whitelist is also OS-correct.
var tunDeviceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,15}$`)

// FriendlyAddrError returns a stable user-facing message for an IP-parse
// failure. The Go stdlib's netip.ParseAddr error text is intentionally
// dropped — strings like `ParseAddr("10.42.0.22.333"): IPv4 address too
// long` are diagnostic for Go authors but useless to operators typing
// into a form. Callers pass the form field name (or empty for unqualified
// messages) and the operator-supplied value so the message identifies
// both what is wrong and where.
func FriendlyAddrError(field, value string) string {
	if strings.TrimSpace(field) == "" {
		return fmt.Sprintf("%q is not a valid IPv4 or IPv6 address", value)
	}
	return fmt.Sprintf("%s: %q is not a valid IPv4 or IPv6 address", field, value)
}

// FriendlyPrefixError is the CIDR counterpart of FriendlyAddrError.
func FriendlyPrefixError(field, value string) string {
	if strings.TrimSpace(field) == "" {
		return fmt.Sprintf("%q is not a valid CIDR (IPv4 or IPv6)", value)
	}
	return fmt.Sprintf("%s: %q is not a valid CIDR (IPv4 or IPv6)", field, value)
}

// ValidateIPAddr is a thin wrapper around netip.ParseAddr that converts
// a failure into a user-facing FriendlyAddrError. Returns the parsed
// address on success.
func ValidateIPAddr(field, value string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s", FriendlyAddrError(field, value))
	}
	return addr, nil
}

// ValidateCIDR is a thin wrapper around netip.ParsePrefix that converts
// a failure into a user-facing FriendlyPrefixError.
func ValidateCIDR(field, value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%s", FriendlyPrefixError(field, value))
	}
	return prefix, nil
}

// ValidateNetworkCIDRs validates a list of CIDRs for a network. It checks that:
// - The list is non-empty
// - Each CIDR is parseable
// - There are no duplicate CIDRs
// - There are no overlapping CIDRs
func ValidateNetworkCIDRs(cidrs []string) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("at least one CIDR required")
	}

	prefixes := make([]netip.Prefix, len(cidrs))
	normalizedStrs := make(map[string]int)

	for i, cidrStr := range cidrs {
		prefix, err := netip.ParsePrefix(cidrStr)
		if err != nil {
			fieldName := fmt.Sprintf("cidrs[%d]", i)
			msg := FriendlyPrefixError(fieldName, cidrStr)
			return fmt.Errorf("%s", msg)
		}
		prefixes[i] = prefix

		normalized := prefix.String()
		if idx, exists := normalizedStrs[normalized]; exists {
			return fmt.Errorf("cidrs: duplicate CIDR at index %d and %d: %q", idx, i, normalized)
		}
		normalizedStrs[normalized] = i
	}

	for i := 0; i < len(prefixes); i++ {
		for j := i + 1; j < len(prefixes); j++ {
			if prefixes[i].Overlaps(prefixes[j]) {
				return fmt.Errorf("cidrs: CIDR at index %d (%q) overlaps with CIDR at index %d (%q)", i, prefixes[i], j, prefixes[j])
			}
		}
	}

	return nil
}

// ValidateHostAddresses validates a list of overlay addresses for a host. It checks that:
// - The list is non-empty
// - Each address is parseable
// - There are no duplicate addresses
// - The list does not exceed MaxAddressesPerHost
//
// Note: This function does not check containment in parent network CIDRs.
// That validation is the responsibility of the caller (API or web handler)
// which has the parent network context and can provide better error messages.
func ValidateHostAddresses(addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("at least one address required")
	}

	if len(addrs) > MaxAddressesPerHost {
		return fmt.Errorf("maximum %d addresses per host; got %d", MaxAddressesPerHost, len(addrs))
	}

	parsedAddrs := make([]netip.Addr, len(addrs))
	normalizedStrs := make(map[string]int)

	for i, addrStr := range addrs {
		addr, err := netip.ParseAddr(addrStr)
		if err != nil {
			fieldName := fmt.Sprintf("nebula_ips[%d]", i)
			msg := FriendlyAddrError(fieldName, addrStr)
			return fmt.Errorf("%s", msg)
		}
		parsedAddrs[i] = addr

		normalized := addr.String()
		if idx, exists := normalizedStrs[normalized]; exists {
			return fmt.Errorf("nebula_ips: duplicate address at index %d and %d: %q", idx, i, normalized)
		}
		normalizedStrs[normalized] = i
	}

	return nil
}

// ParseUnsafeNetworks parses the prefixes a host advertises as routable
// through itself (Host.UnsafeNetworks) into the form the signer needs.
//
// Each entry must be in canonical masked form (10.0.0.0/24, not 10.0.0.1/24).
// Canonical form is enforced rather than silently masked because the operator
// who types 192.168.1.1/24 is describing the gateway's own address, not the
// prefix it serves, and the distinction matters: Nebula stores what it is
// given and matches the packet's local address against it.
//
// Both the write paths (via ValidateUnsafeNetworks) and the signing paths use
// this, so a certificate can never carry a prefix in a shape validation would
// have rejected.
func ParseUnsafeNetworks(networks []string) ([]netip.Prefix, error) {
	if len(networks) == 0 {
		return nil, nil
	}

	prefixes := make([]netip.Prefix, len(networks))
	for i, s := range networks {
		field := fmt.Sprintf("unsafe_networks[%d]", i)
		prefix, err := ValidateCIDR(field, s)
		if err != nil {
			return nil, err
		}
		if prefix.Masked() != prefix {
			return nil, fmt.Errorf("%s: %q has host bits set; use %q", field, s, prefix.Masked())
		}
		prefixes[i] = prefix
	}

	return prefixes, nil
}

// ValidateUnsafeNetworks validates the prefixes a host advertises as routable
// through itself, against the overlay CIDRs of the network it belongs to. It
// checks that:
//   - Each entry is a parseable CIDR in canonical masked form
//   - There are no duplicates and no overlaps between entries
//   - No entry overlaps one of the network's own overlay CIDRs
//   - The list does not exceed MaxUnsafeNetworksPerHost
//
// An empty list is valid and means "this host routes nothing but itself".
//
// The overlay check is folded in rather than offered separately so no caller
// can run half the validation: an unsafe network overlapping the overlay would
// shadow real mesh peers, because Nebula builds one routing table from the
// certificate's networks and unsafe networks together. Callers with no overlay
// in hand — the mesh importer reading prefixes off an existing certificate —
// pass nil.
//
// Containment checks against the parent network are deliberately absent. An
// unsafe network is by definition outside the overlay — that is what makes it
// unsafe.
func ValidateUnsafeNetworks(networks, overlayCIDRs []string) error {
	if len(networks) > MaxUnsafeNetworksPerHost {
		return fmt.Errorf("maximum %d unsafe networks per host; got %d", MaxUnsafeNetworksPerHost, len(networks))
	}

	prefixes, err := ParseUnsafeNetworks(networks)
	if err != nil {
		return err
	}

	seen := make(map[string]int, len(prefixes))
	for i, prefix := range prefixes {
		normalized := prefix.String()
		if idx, exists := seen[normalized]; exists {
			return fmt.Errorf("unsafe_networks: duplicate network at index %d and %d: %q", idx, i, normalized)
		}
		seen[normalized] = i
	}

	for i := 0; i < len(prefixes); i++ {
		for j := i + 1; j < len(prefixes); j++ {
			if prefixes[i].Overlaps(prefixes[j]) {
				return fmt.Errorf("unsafe_networks: network at index %d (%q) overlaps with network at index %d (%q)", i, prefixes[i], j, prefixes[j])
			}
		}
	}

	overlays, err := parsePrefixes(overlayCIDRs)
	if err != nil {
		return err
	}
	for i, prefix := range prefixes {
		for _, overlay := range overlays {
			if prefix.Overlaps(overlay) {
				return fmt.Errorf("unsafe_networks[%d]: %q overlaps the overlay network %q", i, prefix, overlay)
			}
		}
	}

	return nil
}

// parsePrefixes parses a network's own CIDRs, which were validated by
// ValidateNetworkCIDRs on their way in. A failure here means the stored
// network is corrupt, so it surfaces as an error rather than being skipped —
// silently ignoring it would drop the overlap check it was needed for.
func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("network has invalid CIDR %q: %w", c, err)
		}
		out[i] = prefix
	}
	return out, nil
}

// ValidateHostAdvanced rejects obviously broken advanced overrides before
// they reach the database. Empty / zero-value fields mean "inherit
// network default" and pass validation. All error messages use the
// user-facing friendly wrappers so the inline form (web) and the JSON
// API surface identical, stable strings.
func ValidateHostAdvanced(adv *HostAdvanced) error {
	if adv == nil {
		return nil
	}
	if adv.MTU != 0 && (adv.MTU < 576 || adv.MTU > 9216) {
		return fmt.Errorf("advanced.mtu must be between 576 and 9216")
	}
	if adv.ListenHost != "" {
		if _, err := ValidateIPAddr("advanced.listen_host", adv.ListenHost); err != nil {
			return err
		}
	}
	if adv.TunDevice != "" {
		if !tunDeviceRe.MatchString(adv.TunDevice) {
			return fmt.Errorf("advanced.tun_device must match [A-Za-z0-9_-]{1,15}")
		}
	}
	for i, r := range adv.UnsafeRoutes {
		if r.Route == "" || r.Via == "" {
			return fmt.Errorf("advanced.unsafe_routes[%d]: route and via are required", i)
		}
		if _, err := ValidateCIDR(fmt.Sprintf("advanced.unsafe_routes[%d].route", i), r.Route); err != nil {
			return err
		}
		if _, err := ValidateIPAddr(fmt.Sprintf("advanced.unsafe_routes[%d].via", i), r.Via); err != nil {
			return err
		}
	}
	if len(adv.FirewallInbound) > MaxHostFirewallRules {
		return fmt.Errorf("advanced.firewall_inbound: at most %d rules allowed", MaxHostFirewallRules)
	}
	for i, r := range adv.FirewallInbound {
		if err := validateHostFirewallRule(r); err != nil {
			return fmt.Errorf("advanced.firewall_inbound[%d]: %w", i, err)
		}
	}
	return nil
}

// MaxGroupNameLen bounds a group name. Group names are embedded in the signed
// Nebula certificate and distributed to every peer, so without a cap an
// operator could bloat certs mesh-wide (#186). It lives here, in the domain
// layer, because both certificate group validation and firewall rule
// validation must enforce the same bound.
const MaxGroupNameLen = 64

func validateHostFirewallRule(r HostFirewallRule) error {
	if r.Port == "" || r.Proto == "" {
		return fmt.Errorf("port and proto are required")
	}
	if err := ValidateFirewallSelectors(r.Group, r.Cidr); err != nil {
		return err
	}
	switch r.Proto {
	case "any", "tcp", "udp", "icmp":
	default:
		return fmt.Errorf("proto must be one of any, tcp, udp, icmp")
	}
	if len(r.Group) > MaxGroupNameLen {
		return fmt.Errorf("group must be at most %d characters", MaxGroupNameLen)
	}
	if err := ValidateFirewallCIDR("local_cidr", r.LocalCidr); err != nil {
		return err
	}
	return validateFirewallPort(r.Port)
}

// ValidateFirewallSelectors enforces that a firewall rule carries exactly one
// peer selector. Nebula OR's `group` and `cidr` (a rule listing both matches
// peers in the group *or* peers in the prefix, which is wider than either),
// so the two are mutually exclusive here; expressing that union takes two
// rules. An empty pair is rejected because Nebula treats a rule with no
// selector as match-any, a broader allow than any operator intends.
func ValidateFirewallSelectors(group, cidr string) error {
	switch {
	case group == "" && cidr == "":
		return fmt.Errorf("a group or cidr is required")
	case group != "" && cidr != "":
		return fmt.Errorf("group and cidr are mutually exclusive; use one rule per selector")
	}
	return ValidateFirewallCIDR("cidr", cidr)
}

// ValidateFirewallCIDR validates a Nebula firewall `cidr` / `local_cidr`
// value: empty (field unset), the literal "any" (any address of any family),
// or a parseable prefix such as 10.0.0.0/24 or fd00::/8.
func ValidateFirewallCIDR(field, value string) error {
	if value == "" || value == "any" {
		return nil
	}
	_, err := ValidateCIDR(field, value)
	return err
}

// validateFirewallPort accepts "any", a single port 1-65535, or an
// ascending range "a-b" within those bounds — the forms Nebula's firewall
// accepts for the port field.
func validateFirewallPort(port string) error {
	if port == "any" {
		return nil
	}
	parse := func(s string) (int, error) {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("port must be \"any\", a port between 1 and 65535, or a range \"a-b\"")
		}
		return n, nil
	}
	lo, hi, isRange := strings.Cut(port, "-")
	if !isRange {
		_, err := parse(port)
		return err
	}
	loN, err := parse(lo)
	if err != nil {
		return err
	}
	hiN, err := parse(hi)
	if err != nil {
		return err
	}
	if loN > hiN {
		return fmt.Errorf("port range start must not exceed its end")
	}
	return nil
}
