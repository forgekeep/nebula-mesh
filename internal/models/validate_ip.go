package models

import (
	"fmt"
	"net/netip"
	"strings"
)

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
		if strings.ContainsAny(adv.TunDevice, " \t\n/") {
			return fmt.Errorf("advanced.tun_device must not contain whitespace or slashes")
		}
		if len(adv.TunDevice) > 32 {
			return fmt.Errorf("advanced.tun_device must be at most 32 characters")
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
