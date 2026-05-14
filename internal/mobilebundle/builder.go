package mobilebundle

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"github.com/juev/nebula-mesh/internal/configgen"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

var ErrNotMobile = errors.New("mobilebundle: host is not a mobile host")

// Build mints a fresh X25519 keypair + cert for a mobile host, persists the
// cert via store, and returns a self-contained Nebula YAML bundle with
// inline PEM for ca/cert/key. The private key is not persisted server-side
// — it lives only in the returned bytes.
func Build(ctx context.Context, s store.Store, resolver interface{ LoadByID(context.Context, string) (*pki.CAManager, error) }, host *models.Host) ([]byte, error) {
	if host.Kind != models.HostKindMobile {
		return nil, ErrNotMobile
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

	// Get network.
	network, err := s.GetNetwork(ctx, host.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}

	// Build host prefix.
	hostPrefix, err := buildHostPrefix(host.NebulaIP, network.CIDR)
	if err != nil {
		return nil, fmt.Errorf("build host prefix: %w", err)
	}

	// Sign certificate.
	hostCert, err := caMgr.Sign(pki.SignRequest{
		Name:      host.Name,
		PublicKey: pub,
		Networks:  []netip.Prefix{hostPrefix},
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

	// Persist certificate.
	if host.Status == models.HostStatusPending {
		if err := s.SaveCertificateAndEnrollHost(ctx, host.ID, certPEM, fp, hostCert.NotBefore(), hostCert.NotAfter()); err != nil {
			return nil, fmt.Errorf("save certificate: %w", err)
		}
	} else {
		if err := s.SaveCertificateAndUpdateHostCert(ctx, host.ID, certPEM, fp, hostCert.NotBefore(), hostCert.NotAfter()); err != nil {
			return nil, fmt.Errorf("rotate certificate: %w", err)
		}
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

	// Compose GeneratorInput with inline PEM.
	input := configgen.GeneratorInput{
		HostName:    host.Name,
		NebulaIP:    host.NebulaIP,
		CACertPEM:   string(caPEM),
		CertPEM:     string(certPEM),
		KeyPEM:      string(privPEM),
		Lighthouses: lighthouses,
		FirewallInbound: []configgen.FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []configgen.FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	// Apply advanced overrides if present.
	if adv := host.Advanced; adv != nil {
		input.PunchyOverride = adv.Punchy
		input.ListenHost = adv.ListenHost
		input.MTU = adv.MTU
		input.TunDevice = adv.TunDevice
		for _, u := range adv.UnsafeRoutes {
			input.UnsafeRoutes = append(input.UnsafeRoutes, configgen.AdvancedUnsafeRoute{Route: u.Route, Via: u.Via})
		}
	}

	return configgen.Generate(input)
}

// buildHostPrefix mirrors the logic from internal/api/helpers.go.
// Parses hostIP and networkCIDR, validates they belong to the same IP family,
// and returns a prefix combining the host address with the network mask.
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
		port := h.ListenPort
		if port == 0 {
			port = 4242
		}
		result = append(result, configgen.LighthouseInfo{
			NebulaIP:   h.NebulaIP,
			PublicAddr: fmt.Sprintf("%s:%d", h.PublicIP, port),
		})
	}
	return result, nil
}
