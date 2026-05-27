package api

import (
	"context"
	"net/netip"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// fuzzIPStore is a minimal store.Store for FuzzValidateIP. validateHostIPs
// touches only GetNetwork and ListHosts, so every other method is left to the
// nil embedded interface — calling one would panic and surface an unexpected
// new dependency instead of silently passing.
type fuzzIPStore struct {
	store.Store
	net   *models.Network
	hosts []*models.Host
}

func (f *fuzzIPStore) GetNetwork(context.Context, string) (*models.Network, error) {
	if f.net == nil {
		return nil, store.ErrNotFound
	}
	return f.net, nil
}

func (f *fuzzIPStore) ListHosts(context.Context, store.HostFilter) ([]*models.Host, error) {
	return f.hosts, nil
}

// FuzzValidateIP drives validateHostIPs with random network CIDR sets and
// requested addresses (ADR 0009 Tier 1). The safety property is
// one-directional: whenever validation *accepts*, that acceptance must be
// sound — every address parses, lands inside one configured CIDR, is not an
// IPv4 network/broadcast address, is unique within the request, and collides
// with no existing host. A false accept is an overlay-IP collision or an
// out-of-range address reaching the data layer. The dual-family case (a
// network carrying both a v4 and a v6 CIDR) falls out of fuzzing both CIDRs
// independently. The target must also never panic.
//
//	go test ./internal/api/ -run '^$' -fuzz='^FuzzValidateIP$'
func FuzzValidateIP(f *testing.F) {
	f.Add("10.0.0.0/24", "fd00::/64", "10.0.0.5", "fd00::5", "10.0.0.9")
	f.Add("10.0.0.0/30", "", "10.0.0.0", "10.0.0.3", "")          // network + broadcast (reserved)
	f.Add("192.168.0.0/16", "", "192.168.1.1", "192.168.1.1", "") // duplicate within request
	f.Add("", "", "", "", "")

	f.Fuzz(func(t *testing.T, cidr1, cidr2, ip1, ip2, existingIP string) {
		netCIDRs := fuzzNonEmpty(cidr1, cidr2)
		reqIPs := fuzzNonEmpty(ip1, ip2)

		st := &fuzzIPStore{net: &models.Network{ID: "net1", CIDRs: netCIDRs}}
		if existingIP != "" {
			st.hosts = []*models.Host{{ID: "other", Name: "other", NebulaIPs: []string{existingIP}}}
		}

		// A rejection — or a malformed-CIDR/network error — is always allowed;
		// only an *acceptance* carries a soundness obligation.
		if err := validateHostIPs(context.Background(), st, "net1", reqIPs, ""); err != nil {
			return
		}

		// Accepted: re-derive the invariant independently. validateHostIPs only
		// returns nil when every CIDR parsed, so this prefix list matches the
		// one it used. Note: this re-check deliberately reuses forbiddenIPv4Reserved
		// and the same Is4() family gate, so it asserts the accept path is
		// self-consistent — a bug rooted in those shared helpers (e.g. how a
		// 4-in-6 address is classified) would pass both sides by construction.
		prefixes := make([]netip.Prefix, 0, len(netCIDRs))
		for _, c := range netCIDRs {
			if p, perr := netip.ParsePrefix(c); perr == nil {
				prefixes = append(prefixes, p)
			}
		}
		seen := make(map[string]bool, len(reqIPs))
		for _, ip := range reqIPs {
			addr, perr := netip.ParseAddr(ip)
			if perr != nil {
				t.Fatalf("accepted an unparseable IP %q (cidrs=%v)", ip, netCIDRs)
			}
			var containing netip.Prefix
			inRange := false
			for _, p := range prefixes {
				if p.Contains(addr) {
					containing, inRange = p, true
					break
				}
			}
			if !inRange {
				t.Fatalf("accepted out-of-range IP %q (cidrs=%v)", ip, netCIDRs)
			}
			if addr.Is4() && forbiddenIPv4Reserved(containing, addr) {
				t.Fatalf("accepted reserved IPv4 %q in %s", ip, containing)
			}
			if seen[ip] {
				t.Fatalf("accepted duplicate IP %q within request", ip)
			}
			seen[ip] = true
			if existingIP != "" && ip == existingIP {
				t.Fatalf("accepted IP %q already held by another host", ip)
			}
		}
	})
}

func fuzzNonEmpty(ss ...string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
