package models

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

func TestValidateUnsafeNetworks_Accepts(t *testing.T) {
	cases := []struct {
		name     string
		networks []string
	}{
		{"empty means advertises nothing", nil},
		{"empty slice", []string{}},
		{"single ipv4 prefix", []string{"192.168.1.0/24"}},
		{"ipv6 prefix", []string{"fd00:dead::/64"}},
		{"several disjoint prefixes", []string{"192.168.1.0/24", "10.10.0.0/16", "fd00::/8"}},
		{"single host route", []string{"192.168.1.7/32"}},
		{"default route", []string{"0.0.0.0/0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateUnsafeNetworks(tc.networks, nil); err != nil {
				t.Errorf("ValidateUnsafeNetworks(%v) = %v, want nil", tc.networks, err)
			}
		})
	}
}

func TestValidateUnsafeNetworks_Rejects(t *testing.T) {
	// Distinct, non-overlapping /24s so the cap case fails on the count.
	overCap := make([]string, MaxUnsafeNetworksPerHost+1)
	for i := range overCap {
		overCap[i] = "10." + strconv.Itoa(i) + ".0.0/24"
	}

	cases := []struct {
		name     string
		networks []string
		overlay  []string
		// wantSubstring identifies which constraint fired, so a rule that
		// starts rejecting for the wrong reason still fails the test.
		wantSubstring string
	}{
		{"prefix length out of range", []string{"192.168.1.0/33"}, nil, "unsafe_networks[0]"},
		{"bare address, no prefix length", []string{"192.168.1.1"}, nil, "unsafe_networks[0]"},
		// The likeliest operator slip: typing the gateway's own LAN address
		// where the prefix it serves belongs. Nebula matches the packet's
		// local address against what the cert carries, so silently masking
		// this would hide a real misunderstanding.
		{"host bits set", []string{"192.168.1.1/24"}, nil, "192.168.1.0/24"},
		{"duplicate entries", []string{"192.168.1.0/24", "192.168.1.0/24"}, nil, "duplicate"},
		{"entries overlap each other", []string{"192.168.0.0/16", "192.168.1.0/24"}, nil, "overlaps"},
		{"over the per-host cap", overCap, nil, "maximum"},
		// An unsafe network overlapping the overlay would shadow real mesh
		// peers: Nebula builds one routing table from the certificate's
		// networks and unsafe networks together.
		{"is the overlay itself", []string{"172.31.16.0/24"}, []string{"172.31.16.0/24"}, "overlay"},
		{"sits inside the overlay", []string{"172.31.16.128/25"}, []string{"172.31.16.0/24"}, "overlay"},
		{"contains the overlay", []string{"172.31.0.0/16"}, []string{"172.31.16.0/24"}, "overlay"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateUnsafeNetworks(tc.networks, tc.overlay)
			if err == nil {
				t.Fatalf("ValidateUnsafeNetworks(%v, %v) = nil, want an error", tc.networks, tc.overlay)
			}
			if !strings.Contains(err.Error(), tc.wantSubstring) {
				t.Errorf("error %q should mention %q", err, tc.wantSubstring)
			}
		})
	}
}

func TestValidateUnsafeNetworks_ErrorHidesStdlibInternals(t *testing.T) {
	err := ValidateUnsafeNetworks([]string{"192.168.1.0/33"}, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), "ParsePrefix") || strings.Contains(err.Error(), "netip:") {
		t.Errorf("operator-facing error must not leak stdlib internals; got %q", err)
	}
}

func TestValidateUnsafeNetworks_AllowsPrefixDisjointFromOverlay(t *testing.T) {
	if err := ValidateUnsafeNetworks([]string{"192.168.1.0/24"}, []string{"172.31.16.0/24"}); err != nil {
		t.Errorf("a LAN prefix disjoint from the overlay must be accepted; got %v", err)
	}
}

// A corrupt stored network must not silently skip the overlap check — that is
// the check standing between an operator and a blackholed overlay peer.
func TestValidateUnsafeNetworks_RejectsUnparseableOverlay(t *testing.T) {
	err := ValidateUnsafeNetworks([]string{"192.168.1.0/24"}, []string{"not-a-cidr"})
	if err == nil {
		t.Fatal("expected an error for an unparseable overlay CIDR")
	}
	if !strings.Contains(err.Error(), "invalid CIDR") {
		t.Errorf("error should name the bad network CIDR; got %q", err)
	}
}

func TestParseUnsafeNetworks(t *testing.T) {
	got, err := ParseUnsafeNetworks([]string{"192.168.1.0/24", "fd00::/8"})
	if err != nil {
		t.Fatalf("ParseUnsafeNetworks: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("fd00::/8"),
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseUnsafeNetworks_EmptyIsNil(t *testing.T) {
	got, err := ParseUnsafeNetworks(nil)
	if err != nil {
		t.Fatalf("ParseUnsafeNetworks(nil): %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil so the signer emits no unsafe networks", got)
	}
}

// The signing paths call ParseUnsafeNetworks directly on stored values. It has
// to reject the same shapes validation does, or a hand-edited row could put a
// prefix into a certificate that the API would have refused.
func TestParseUnsafeNetworks_RejectsWhatValidationRejects(t *testing.T) {
	for _, bad := range []string{"192.168.1.1/24", "192.168.1.1", "garbage"} {
		if _, err := ParseUnsafeNetworks([]string{bad}); err == nil {
			t.Errorf("ParseUnsafeNetworks(%q) = nil error, want rejection", bad)
		}
	}
}
