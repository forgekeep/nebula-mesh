package api

import (
	"fmt"
	"net/netip"
)

// buildHostPrefix parses hostIP and networkCIDR, validates they belong to the same
// IP family (v4/v6), and returns a prefix combining the host address with the network mask.
func buildHostPrefix(hostIP, networkCIDR string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(networkCIDR)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse CIDR: %w", err)
	}

	hostAddr, err := netip.ParseAddr(hostIP)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse host IP: %w", err)
	}

	if hostAddr.Is4() != prefix.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("IP family mismatch: host %s vs network %s", hostIP, networkCIDR)
	}

	return netip.PrefixFrom(hostAddr, prefix.Bits()), nil
}
