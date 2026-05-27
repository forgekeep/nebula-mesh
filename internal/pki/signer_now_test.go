package pki

import (
	"net/netip"
	"testing"
	"time"
)

// TestSign_NowSetsValidity verifies that SignRequest.Now drives the cert
// validity window exactly (no wall-clock slack), so the simulation harness can
// mint certs at a controlled instant. The zero value falls back to time.Now(),
// covered by the other signer tests.
func TestSign_NowSetsValidity(t *testing.T) {
	ca, err := NewCA("test-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := generateHostKeypair(t)

	// An instant comfortably inside the freshly-minted CA's validity window.
	now := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	dur := 30 * 24 * time.Hour

	c, err := ca.Sign(SignRequest{
		Name:      "host-now",
		PublicKey: pub,
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.5/24")},
		Duration:  dur,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if c.NotBefore().Unix() != now.Unix() {
		t.Errorf("NotBefore = %s, want injected Now %s", c.NotBefore(), now)
	}
	if want := now.Add(dur); c.NotAfter().Unix() != want.Unix() {
		t.Errorf("NotAfter = %s, want %s", c.NotAfter(), want)
	}
}
