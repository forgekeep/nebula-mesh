package models

import (
	"fmt"
	"net/netip"
	"regexp"
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
	return nil
}
