package pki

import (
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

func generateHostKeypair(t *testing.T) (pub, priv []byte) {
	t.Helper()
	priv = make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newTestCA(t *testing.T) *CAManager {
	t.Helper()
	ca, err := NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestSign(t *testing.T) {
	ca := newTestCA(t)
	pub, _ := generateHostKeypair(t)

	req := SignRequest{
		Name:     "host1",
		PublicKey: pub,
		Networks: []netip.Prefix{netip.MustParsePrefix("192.168.100.5/24")},
		Groups:   []string{"web", "workers"},
		Duration: 8 * time.Hour,
	}

	hostCert, err := ca.Sign(req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if hostCert.Name() != "host1" {
		t.Errorf("name = %q, want %q", hostCert.Name(), "host1")
	}
	if hostCert.IsCA() {
		t.Error("expected IsCA to be false")
	}

	networks := hostCert.Networks()
	if len(networks) != 1 || networks[0] != netip.MustParsePrefix("192.168.100.5/24") {
		t.Errorf("networks = %v, want [192.168.100.5/24]", networks)
	}

	groups := hostCert.Groups()
	if len(groups) != 2 || groups[0] != "web" || groups[1] != "workers" {
		t.Errorf("groups = %v, want [web workers]", groups)
	}
}

func TestSign_VerifyWithCAPool(t *testing.T) {
	ca := newTestCA(t)
	pub, _ := generateHostKeypair(t)

	hostCert, err := ca.Sign(SignRequest{
		Name:      "verified-host",
		PublicKey: pub,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		Duration:  1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify using CAPool
	certPEM, err := ca.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	pool, err := cert.NewCAPoolFromPEM(certPEM)
	if err != nil {
		t.Fatalf("NewCAPoolFromPEM: %v", err)
	}

	_, err = pool.VerifyCertificate(time.Now(), hostCert)
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
}

func TestSign_ExpiredCA(t *testing.T) {
	// Create CA with very short duration (already expired by the time we sign)
	ca, err := NewCA("expired-ca", -1*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	pub, _ := generateHostKeypair(t)
	_, err = ca.Sign(SignRequest{
		Name:      "host",
		PublicKey: pub,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		Duration:  1 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected error signing with expired CA, got nil")
	}
}

func TestSign_CertPEM(t *testing.T) {
	ca := newTestCA(t)
	pub, _ := generateHostKeypair(t)

	hostCert, err := ca.Sign(SignRequest{
		Name:      "pem-host",
		PublicKey: pub,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		Duration:  1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pem, err := hostCert.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}
	if len(pem) == 0 {
		t.Error("PEM is empty")
	}

	// Round-trip
	parsed, _, err := cert.UnmarshalCertificateFromPEM(pem)
	if err != nil {
		t.Fatalf("UnmarshalCertificateFromPEM: %v", err)
	}
	if parsed.Name() != "pem-host" {
		t.Errorf("parsed name = %q, want %q", parsed.Name(), "pem-host")
	}
}

func TestSign_MultiPrefix_V2_RoundTrip(t *testing.T) {
	ca := newTestCA(t)
	pub, _ := generateHostKeypair(t)

	// Create request with multiple prefixes (dual-family)
	req := SignRequest{
		Name:      "host1",
		PublicKey: pub,
		Networks: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.5/24"),
			netip.MustParsePrefix("fd00::5/64"),
		},
		Groups:   nil,
		Duration: 1 * time.Hour,
	}

	hostCert, err := ca.Sign(req)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify certificate version is V2
	if hostCert.Version() != cert.Version2 {
		t.Errorf("version = %d, want %d", hostCert.Version(), cert.Version2)
	}

	// Verify networks count and order
	networks := hostCert.Networks()
	if len(networks) != 2 {
		t.Fatalf("len(networks) = %d, want 2", len(networks))
	}

	// Check exact order and values
	if networks[0].String() != "10.0.0.5/24" {
		t.Errorf("networks[0] = %s, want 10.0.0.5/24", networks[0].String())
	}
	if networks[1].String() != "fd00::5/64" {
		t.Errorf("networks[1] = %s, want fd00::5/64", networks[1].String())
	}

	// Round-trip: marshal to PEM and unmarshal
	pem, err := hostCert.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}

	parsed, _, err := cert.UnmarshalCertificateFromPEM(pem)
	if err != nil {
		t.Fatalf("UnmarshalCertificateFromPEM: %v", err)
	}

	// Verify parsed cert preserves multi-prefix and order
	parsedNetworks := parsed.Networks()
	if len(parsedNetworks) != 2 {
		t.Fatalf("parsed networks len = %d, want 2", len(parsedNetworks))
	}
	if parsedNetworks[0].String() != "10.0.0.5/24" {
		t.Errorf("parsed networks[0] = %s, want 10.0.0.5/24", parsedNetworks[0].String())
	}
	if parsedNetworks[1].String() != "fd00::5/64" {
		t.Errorf("parsed networks[1] = %s, want fd00::5/64", parsedNetworks[1].String())
	}
}
