package api

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// hostIPValidationError marks errors that the API layer should surface as 400.
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

// validateHostIP checks that ip is syntactically valid, falls inside the
// network's CIDR, is not the network or broadcast address (IPv4), and is
// not already used by another host in the same network. The optional
// excludeHostID lets the caller exclude the host being edited from the
// uniqueness check so re-saving without changing the IP succeeds.
func validateHostIP(ctx context.Context, s store.Store, networkID, ip, excludeHostID string) error {
	if ip == "" {
		return &hostIPValidationError{msg: "nebula_ip is required"}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return &hostIPValidationError{msg: fmt.Sprintf("invalid nebula_ip: %s", err.Error())}
	}

	net, err := s.GetNetwork(ctx, networkID)
	if errors.Is(err, store.ErrNotFound) {
		return &hostIPValidationError{msg: "network not found"}
	}
	if err != nil {
		return fmt.Errorf("get network: %w", err)
	}

	prefix, err := netip.ParsePrefix(net.CIDR)
	if err != nil {
		return fmt.Errorf("network %q has invalid CIDR %q: %w", net.ID, net.CIDR, err)
	}
	if !prefix.Contains(addr) {
		return &hostIPValidationError{msg: fmt.Sprintf("nebula_ip %s is outside the network CIDR %s", ip, net.CIDR)}
	}

	if addr.Is4() {
		if forbiddenIPv4Reserved(prefix, addr) {
			return &hostIPValidationError{msg: fmt.Sprintf("nebula_ip %s is reserved (network or broadcast address of %s)", ip, net.CIDR)}
		}
	}

	hosts, err := s.ListHosts(ctx, store.HostFilter{NetworkID: networkID, Limit: 0})
	if err != nil {
		return fmt.Errorf("list hosts: %w", err)
	}
	for _, h := range hosts {
		if h.ID == excludeHostID {
			continue
		}
		if h.NebulaIP == ip {
			return &hostIPValidationError{msg: fmt.Sprintf("nebula_ip %s is already assigned to host %q in this network", ip, h.Name)}
		}
	}
	return nil
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
