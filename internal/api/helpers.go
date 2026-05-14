package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/juev/nebula-mesh/internal/models"
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

// buildHostPrefixes parses each hostAddr and finds a matching parent prefix from network.CIDRs.
// For each hostAddr[i]:
// - Parses the address
// - Finds the first CIDR that contains it
// - Returns a prefix using the host address with the parent's mask bits
// If no parent contains the address, returns an error with the address index.
func buildHostPrefixes(network *models.Network, hostAddrs []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, len(hostAddrs))

	for i, hostAddr := range hostAddrs {
		addr, err := netip.ParseAddr(hostAddr)
		if err != nil {
			msg := models.FriendlyAddrError("nebula_ips["+strconv.Itoa(i)+"]", hostAddr)
			return nil, fmt.Errorf("%s", msg)
		}

		var found netip.Prefix
		var foundParent bool
		for _, cidr := range network.CIDRs {
			parent, err := netip.ParsePrefix(cidr)
			if err != nil {
				return nil, fmt.Errorf("network has invalid CIDR %q: %w", cidr, err)
			}

			if parent.Contains(addr) {
				found = parent
				foundParent = true
				break
			}
		}

		if !foundParent {
			return nil, fmt.Errorf("nebula_ips[%d]: %q is not within any network CIDR", i, hostAddr)
		}

		result[i] = netip.PrefixFrom(addr, found.Bits())
	}

	return result, nil
}

// decodeJSONStrict decodes JSON from request body with DisallowUnknownFields enabled.
// On unknown field, returns helpful message suggesting legacy field names.
func decodeJSONStrict(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		errStr := err.Error()

		// Parse unknown field from "json: unknown field \"cidr\"" format
		if strings.Contains(errStr, "unknown field") {
			// Extract field name from error message
			parts := strings.Split(errStr, "\"")
			if len(parts) >= 2 {
				fieldName := parts[1]
				// Suggest proper plural form for known legacy fields
				if fieldName == "cidr" {
					return fmt.Errorf("unknown field 'cidr' — use 'cidrs' (array of CIDRs)")
				}
				if fieldName == "nebula_ip" {
					return fmt.Errorf("unknown field 'nebula_ip' — use 'nebula_ips' (array of IPs)")
				}
				return fmt.Errorf("unknown field '%s'", fieldName)
			}
		}
		return err
	}
	return nil
}
