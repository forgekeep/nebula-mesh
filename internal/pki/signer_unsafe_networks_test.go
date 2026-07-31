package pki

import (
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
)

// A gateway's certificate must carry the prefixes it is allowed to route for.
// Nebula authorizes routing on the certificate, not on config: with an empty
// unsafe-networks list the gateway silently refuses to route, and both ends
// drop the traffic in Firewall.Drop (ErrInvalidLocalIP) before consulting a
// single firewall rule. That made per-host unsafe_routes unusable end to end.
func TestSign_CarriesUnsafeNetworks(t *testing.T) {
	ca := newTestCA(t)
	pub, _ := generateHostKeypair(t)

	want := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("10.10.0.0/16"),
	}

	hostCert, err := ca.Sign(SignRequest{
		Name:           "gateway",
		PublicKey:      pub,
		Networks:       []netip.Prefix{netip.MustParsePrefix("172.31.16.250/24")},
		UnsafeNetworks: want,
		Groups:         []string{"gw"},
		Duration:       time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	got := hostCert.UnsafeNetworks()
	if len(got) != len(want) {
		t.Fatalf("unsafe networks = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("unsafe networks[%d] = %v, want %v", i, got[i], want[i])
		}
	}

	// The overlay networks must be untouched by the addition.
	networks := hostCert.Networks()
	if len(networks) != 1 || networks[0] != netip.MustParsePrefix("172.31.16.250/24") {
		t.Errorf("networks = %v, want [172.31.16.250/24]", networks)
	}
}

// An ordinary host asks for nothing and must get a certificate that authorizes
// nothing beyond itself — the field is opt-in, and a stray prefix here would
// widen what every peer accepts from this host.
func TestSign_NoUnsafeNetworksByDefault(t *testing.T) {
	ca := newTestCA(t)
	pub, _ := generateHostKeypair(t)

	hostCert, err := ca.Sign(SignRequest{
		Name:      "plain-host",
		PublicKey: pub,
		Networks:  []netip.Prefix{netip.MustParsePrefix("172.31.16.59/24")},
		Duration:  time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if got := hostCert.UnsafeNetworks(); len(got) != 0 {
		t.Errorf("unsafe networks = %v, want none", got)
	}
}

// The unsafe networks are inside the signed body, not appended alongside it,
// so a cert bearing them still verifies against the issuing CA.
func TestSign_UnsafeNetworksVerifyAgainstCA(t *testing.T) {
	ca := newTestCA(t)
	pub, _ := generateHostKeypair(t)

	hostCert, err := ca.Sign(SignRequest{
		Name:           "gateway",
		PublicKey:      pub,
		Networks:       []netip.Prefix{netip.MustParsePrefix("10.0.0.99/24")},
		UnsafeNetworks: []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")},
		Duration:       time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	certPEM, err := ca.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	pool, err := cert.NewCAPoolFromPEM(certPEM)
	if err != nil {
		t.Fatalf("NewCAPoolFromPEM: %v", err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), hostCert); err != nil {
		t.Errorf("VerifyCertificate: %v", err)
	}
}
