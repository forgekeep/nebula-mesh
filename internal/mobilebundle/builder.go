package mobilebundle

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/mobileconfig"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/revocation"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

var ErrNotMobile = errors.New("mobilebundle: host is not a mobile host")

// Build mints a fresh X25519 keypair + cert for a mobile host, persists the
// cert via store, and returns a self-contained Nebula YAML bundle with
// inline PEM for ca/cert/key. The private key is not persisted server-side
// — it lives only in the returned bytes.
func Build(ctx context.Context, s store.Store, resolver interface {
	LoadByID(context.Context, string) (*pki.CAManager, error)
}, host *models.Host) ([]byte, error) {
	if host.Kind != models.HostKindMobile {
		return nil, ErrNotMobile
	}

	// Durable revocation (GHSA-339v-266x-79xr): refuse to mint a fresh mobile
	// cert for a blocked host or a disabled operator's host. This is the shared
	// chokepoint for both the API and web mobile-bundle handlers; checked before
	// key generation and CA decryption so a revoked host triggers no crypto work.
	if err := revocation.CheckIssuanceAllowed(ctx, s, host); err != nil {
		return nil, err
	}

	// Generate X25519 keypair.
	priv := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, priv); err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}

	// Resolve CA for this host.
	caMgr, err := resolver.LoadByID(ctx, host.CAID)
	if err != nil {
		return nil, fmt.Errorf("resolve CA: %w", err)
	}
	// GHSA-2p2f-px33-4vv5: zeroise the decrypted plaintext CA signing key on
	// every return path. The web mobile-bundle handler passes the real
	// CAResolver straight in and has no Wipe of its own, so wiping here is the
	// shared chokepoint for both callers. Wipe is idempotent and nil-safe, so
	// the API handler's own defer caMgr.Wipe() stays a harmless second pass.
	defer caMgr.Wipe()

	// Get network.
	network, err := s.GetNetwork(ctx, host.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}

	// Build host prefixes.
	prefixes, err := buildHostPrefixes(network, host.NebulaIPs)
	if err != nil {
		return nil, fmt.Errorf("build host prefixes: %w", err)
	}

	// Sign certificate.
	hostCert, err := caMgr.Sign(pki.SignRequest{
		Name:      host.Name,
		PublicKey: pub,
		Networks:  prefixes,
		Groups:    host.Groups,
		Duration:  pki.DefaultMobileCertDuration,
	})
	if err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}

	// Marshal cert to PEM.
	certPEM, err := hostCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal cert: %w", err)
	}

	// Get fingerprint.
	fp, err := hostCert.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("cert fingerprint: %w", err)
	}

	// Get CA cert PEM.
	caPEM, err := caMgr.CACertPEM()
	if err != nil {
		return nil, fmt.Errorf("ca cert PEM: %w", err)
	}

	// Marshal private key to PEM.
	privPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, priv)

	// Get lighthouses.
	lighthouses, err := listLighthouses(ctx, s, host.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("list lighthouses: %w", err)
	}
	relays, err := listRelays(ctx, s, host.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("list relays: %w", err)
	}
	blocklist, err := s.GetBlocklistForCA(ctx, host.CAID)
	if err != nil {
		return nil, fmt.Errorf("get blocklist for config: %w", err)
	}
	mobileSettings, err := loadMobileSettings(ctx, s, host.NetworkID)
	if err != nil {
		return nil, err
	}

	// Resolve the network's firewall policy. Mirrors the agent enroll path
	// (api.renderHostConfig): a network with no stored policy, or an unusable
	// one, falls back to the safe baseline so the bundle is always loadable.
	// This builder has no logger, so the unusable case is silently defaulted;
	// FirewallRulesFromJSON returns the baseline either way.
	fwInbound, fwOutbound := configgen.DefaultFirewallInbound, configgen.DefaultFirewallOutbound
	if val, cfgErr := s.GetNetworkConfig(ctx, host.NetworkID, "firewall"); cfgErr == nil {
		fwInbound, fwOutbound, _ = configgen.FirewallRulesFromJSON(val)
	}

	// Generate config.
	input := configgen.GeneratorInput{
		HostName:         host.Name,
		NebulaIPs:        host.NebulaIPs,
		IsLighthouse:     host.IsLighthouse,
		IsRelay:          host.IsRelay,
		Lighthouses:      lighthouses,
		Relays:           relays,
		CACertPEM:        string(caPEM),
		CertPEM:          string(certPEM),
		KeyPEM:           string(privPEM),
		FirewallInbound:  fwInbound,
		FirewallOutbound: fwOutbound,
		Blocklist:        blocklist,
		Mobile: &configgen.MobileProfile{
			DNSResolvers:        mobileSettings.DNSResolvers,
			MatchDomains:        mobileSettings.MatchDomains,
			AllowPrivateRemotes: mobileSettings.AllowPrivateRemotes,
		},
	}
	if adv := host.Advanced; adv != nil {
		input.PunchyOverride = adv.Punchy
		input.ListenHost = adv.ListenHost
		input.MTU = adv.MTU
		input.TunDevice = adv.TunDevice
		for _, u := range adv.UnsafeRoutes {
			input.UnsafeRoutes = append(input.UnsafeRoutes, configgen.AdvancedUnsafeRoute{Route: u.Route, Via: u.Via})
		}
		for _, fr := range adv.FirewallInbound {
			input.HostFirewallInbound = append(input.HostFirewallInbound, configgen.FirewallRule{Port: fr.Port, Proto: fr.Proto, Group: fr.Group})
		}
	}

	configYAML, err := configgen.Generate(input)
	if err != nil {
		return nil, fmt.Errorf("generate config: %w", err)
	}

	// Persist only after every fallible bundle-generation step succeeds. The
	// private key exists only in configYAML, so an earlier durable write could
	// leave the host enrolled with a certificate it can never use.
	if err := s.SaveCertificateIfIssuanceAllowed(
		ctx, host.ID, host.Status, certPEM, fp, hostCert.NotBefore(), hostCert.NotAfter(),
	); err != nil {
		return nil, fmt.Errorf("persist authorized certificate: %w", err)
	}

	// TODO: Bundle into QR code or download format
	// For now, return the YAML
	return configYAML, nil
}

func loadMobileSettings(ctx context.Context, s store.Store, networkID string) (mobileconfig.Settings, error) {
	raw, err := s.GetNetworkConfig(ctx, networkID, mobileconfig.StoreKey)
	if errors.Is(err, store.ErrNotFound) {
		return mobileconfig.Default(), nil
	}
	if err != nil {
		return mobileconfig.Settings{}, fmt.Errorf("get mobile config: %w", err)
	}
	settings, err := mobileconfig.Decode(raw)
	if err != nil {
		return mobileconfig.Settings{}, fmt.Errorf("decode mobile config: %w", err)
	}
	return settings, nil
}

// buildHostPrefixes mirrors the logic from internal/api/helpers.go.
// Parses each hostAddr and finds a matching parent prefix from network.CIDRs.
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

// listLighthouses mirrors the logic from internal/api/enroll.go.
// Returns every enrolled lighthouse in the given network.
func listLighthouses(ctx context.Context, s store.Store, networkID string) ([]configgen.LighthouseInfo, error) {
	hosts, err := s.ListHosts(ctx, store.HostFilter{
		NetworkID: networkID,
		Status:    models.HostStatusEnrolled,
	})
	if err != nil {
		return nil, err
	}

	result := make([]configgen.LighthouseInfo, 0)
	for _, h := range hosts {
		if !h.IsLighthouse || h.PublicIP == "" {
			continue
		}
		if len(h.NebulaIPs) == 0 {
			continue
		}
		port := h.ListenPort
		if port == 0 {
			port = 4242
		}
		result = append(result, configgen.LighthouseInfo{
			NebulaIPs:  h.NebulaIPs,
			PublicAddr: net.JoinHostPort(h.PublicIP, strconv.Itoa(port)),
		})
	}
	return result, nil
}

// listRelays returns sorted overlay addresses for enrolled relay hosts.
func listRelays(ctx context.Context, s store.Store, networkID string) ([]string, error) {
	hosts, err := s.ListHosts(ctx, store.HostFilter{
		NetworkID: networkID,
		Status:    models.HostStatusEnrolled,
	})
	if err != nil {
		return nil, err
	}

	set := make(map[string]struct{})
	for _, host := range hosts {
		if host.Role != models.HostRoleRelay && !host.IsRelay {
			continue
		}
		for _, address := range host.NebulaIPs {
			set[address] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for address := range set {
		result = append(result, address)
	}
	sort.Strings(result)
	return result, nil
}
