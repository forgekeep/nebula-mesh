package web

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// validateHostIPForNetwork mirrors the API-layer validation used by
// handleCreateHost: it checks that ip parses, that it falls inside the
// network's CIDR, that it is not the IPv4 network/broadcast address, and
// that it is not already used by another non-blocked host in the same
// network. excludeHostID lets callers exclude the host being edited.
func validateHostIPForNetwork(ctx context.Context, s store.Store, networkID, ip, excludeHostID string) error {
	if ip == "" {
		return fmt.Errorf("nebula_ip is required")
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return fmt.Errorf("%s", models.FriendlyAddrError("nebula_ip", ip))
	}

	net, err := s.GetNetwork(ctx, networkID)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("network not found")
	}
	if err != nil {
		return fmt.Errorf("get network: %w", err)
	}

	prefix, err := netip.ParsePrefix(net.CIDR)
	if err != nil {
		return fmt.Errorf("network %q has invalid CIDR %q: %w", net.ID, net.CIDR, err)
	}
	if !prefix.Contains(addr) {
		return fmt.Errorf("nebula_ip %s is outside the network CIDR %s", ip, net.CIDR)
	}

	if addr.Is4() && isIPv4Boundary(prefix, addr) {
		return fmt.Errorf("nebula_ip %s is reserved (network or broadcast address of %s)", ip, net.CIDR)
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
			return fmt.Errorf("nebula_ip %s is already assigned to host %q in this network", ip, h.Name)
		}
	}
	return nil
}

var _ = models.HostStatusBlocked

func isIPv4Boundary(prefix netip.Prefix, addr netip.Addr) bool {
	if prefix.Bits() >= 31 {
		return false
	}
	masked := prefix.Masked()
	if addr == masked.Addr() {
		return true
	}
	maskBits := uint32(0xFFFFFFFF) << (32 - prefix.Bits())
	b := masked.Addr().As4()
	netInt := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	broadcast := netInt | ^maskBits
	ab := addr.As4()
	addrInt := uint32(ab[0])<<24 | uint32(ab[1])<<16 | uint32(ab[2])<<8 | uint32(ab[3])
	return addrInt == broadcast
}
