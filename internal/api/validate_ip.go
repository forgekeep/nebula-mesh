package api

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// hostIPValidationError is the typed error the API layer surfaces as 400
// for any nebula_ip / public_ip / advanced validation failure. The
// message is intentionally pre-formatted via models.FriendlyAddrError /
// models.FriendlyPrefixError so the inline-form Web layer and the JSON
// API return identical, stable strings.

type hostIPValidationError struct {
	msg string
}

func (e *hostIPValidationError) Error() string { return e.msg }

// IsHostIPValidationError reports whether err is a user-facing validation
// failure rather than an internal error.
func IsHostIPValidationError(err error) bool {
	var v *hostIPValidationError
	return errors.As(err, &v)
}

// newHostIPValidationError wraps a friendly message in the typed error
// that the handler dispatch chain expects.
func newHostIPValidationError(msg string) error {
	return &hostIPValidationError{msg: msg}
}

var _ = models.HostStatusBlocked

// forbiddenIPv4Reserved reports whether addr is the network or broadcast
// address of an IPv4 prefix. For /31 and /32 prefixes RFC 3021 / point-to-point
// usage allows the boundary addresses, so we skip the check there.
func forbiddenIPv4Reserved(prefix netip.Prefix, addr netip.Addr) bool {
	if prefix.Bits() >= 31 {
		return false
	}
	masked := prefix.Masked()
	if addr == masked.Addr() {
		return true
	}
	// Broadcast = last address in the prefix.
	maskBytes := uint32(0xFFFFFFFF) << (32 - prefix.Bits())
	netInt := ipv4ToUint32(masked.Addr())
	broadcast := netInt | ^maskBytes
	return ipv4ToUint32(addr) == broadcast
}

func ipv4ToUint32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// validateHostIPs checks that each IP in the slice:
// - is syntactically valid
// - falls inside at least one network CIDR
// - is not a network or broadcast address (IPv4)
// - is unique within the slice
// - is not already used by another host (excluding excludeHostID)
func validateHostIPs(ctx context.Context, s store.Store, networkID string, ips []string, excludeHostID string) error {
	if len(ips) == 0 {
		return newHostIPValidationError("nebula_ips is required")
	}

	net, err := s.GetNetwork(ctx, networkID)
	if errors.Is(err, store.ErrNotFound) {
		return newHostIPValidationError("network not found")
	}
	if err != nil {
		return fmt.Errorf("get network: %w", err)
	}

	if len(net.CIDRs) == 0 {
		return fmt.Errorf("network %q has no CIDRs configured", net.ID)
	}

	var prefixes []netip.Prefix
	for _, cidr := range net.CIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("network %q has invalid CIDR %q: %w", net.ID, cidr, err)
		}
		prefixes = append(prefixes, prefix)
	}

	// Validate each IP
	seenIPs := make(map[string]bool)
	for i, ip := range ips {
		if ip == "" {
			return newHostIPValidationError(fmt.Sprintf("nebula_ips[%d] is required", i))
		}

		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return newHostIPValidationError(models.FriendlyAddrError(fmt.Sprintf("nebula_ips[%d]", i), ip))
		}

		// Check if IP falls inside at least one CIDR
		var contains bool
		var containingPrefix netip.Prefix
		for _, prefix := range prefixes {
			if prefix.Contains(addr) {
				contains = true
				containingPrefix = prefix
				break
			}
		}
		if !contains {
			cidrsStr := net.CIDRs[0]
			for _, c := range net.CIDRs[1:] {
				cidrsStr += ", " + c
			}
			return newHostIPValidationError(fmt.Sprintf("nebula_ips[%d] %s is outside the network CIDRs: %s", i, ip, cidrsStr))
		}

		// Check IPv4 reserved addresses
		if addr.Is4() && forbiddenIPv4Reserved(containingPrefix, addr) {
			return newHostIPValidationError(fmt.Sprintf("nebula_ips[%d] %s is reserved (network or broadcast address of %s)", i, ip, containingPrefix))
		}

		// Check for duplicates within the slice
		if seenIPs[ip] {
			return newHostIPValidationError(fmt.Sprintf("nebula_ips[%d] %s is duplicated within the address list", i, ip))
		}
		seenIPs[ip] = true
	}

	// Check global uniqueness (across other hosts)
	hosts, err := s.ListHosts(ctx, store.HostFilter{NetworkID: networkID, Limit: 0})
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	for _, h := range hosts {
		if h.ID == excludeHostID {
			continue
		}
		for _, hIP := range h.NebulaIPs {
			if seenIPs[hIP] {
				return newHostIPValidationError(fmt.Sprintf("nebula_ip %s is already assigned to host %q in this network", hIP, h.Name))
			}
		}
	}

	return nil
}
