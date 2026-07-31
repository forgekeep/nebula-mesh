package models

import (
	"strings"
	"testing"
)

// Unsafe networks live inside the certificate, so editing them is inert until
// a new certificate is issued — exactly like Name, NebulaIPs and Groups. If
// this ever stopped triggering a re-issuance, the operator would set the field
// in the UI, see it saved, and still watch every packet get dropped.
func TestCertIdentityChanged_UnsafeNetworks(t *testing.T) {
	before := &Host{Name: "gw", NebulaIPs: []string{"10.0.0.99"}}
	after := &Host{Name: "gw", NebulaIPs: []string{"10.0.0.99"}, UnsafeNetworks: []string{"192.168.1.0/24"}}

	if !CertIdentityChanged(before, after) {
		t.Error("adding an unsafe network must schedule a certificate re-issuance")
	}
	if !CertIdentityChanged(after, before) {
		t.Error("removing an unsafe network must schedule a certificate re-issuance")
	}
}

func TestCertIdentityChanged_UnsafeNetworksReorder(t *testing.T) {
	a := &Host{Name: "gw", UnsafeNetworks: []string{"192.168.1.0/24", "10.10.0.0/16"}}
	b := &Host{Name: "gw", UnsafeNetworks: []string{"10.10.0.0/16", "192.168.1.0/24"}}

	if !CertIdentityChanged(a, b) {
		t.Error("reordering unsafe networks changes the signed certificate body, so it must re-issue")
	}
}

func TestCertIdentityChanged_UnsafeNetworksUnchanged(t *testing.T) {
	a := &Host{Name: "gw", UnsafeNetworks: []string{"192.168.1.0/24"}}
	b := &Host{Name: "gw", UnsafeNetworks: []string{"192.168.1.0/24"}}

	if CertIdentityChanged(a, b) {
		t.Error("an identical host must not schedule a re-issuance")
	}
}

// nil and empty both mean "advertises nothing"; they survive a store or JSON
// round trip as different values, and must not look like an edit.
func TestCertIdentityChanged_UnsafeNetworksNilVsEmpty(t *testing.T) {
	a := &Host{Name: "gw", UnsafeNetworks: nil}
	b := &Host{Name: "gw", UnsafeNetworks: []string{}}

	if CertIdentityChanged(a, b) {
		t.Error("nil and empty unsafe networks are equivalent; no re-issuance")
	}
}

func TestCertificateIdentityFromHost_CopiesUnsafeNetworks(t *testing.T) {
	host := &Host{Name: "gw", UnsafeNetworks: []string{"192.168.1.0/24"}}
	snapshot := CertificateIdentityFromHost(host)

	host.UnsafeNetworks[0] = "10.0.0.0/8"

	if snapshot.UnsafeNetworks[0] != "192.168.1.0/24" {
		t.Errorf("snapshot must not alias the host's slice; got %q", snapshot.UnsafeNetworks[0])
	}
}

func TestHostDiff_ReportsUnsafeNetworks(t *testing.T) {
	before := &Host{Name: "gw"}
	after := &Host{Name: "gw", UnsafeNetworks: []string{"192.168.1.0/24"}}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff: %v", err)
	}
	if !hasChanges {
		t.Fatal("expected the diff to report a change")
	}
	if !strings.Contains(string(diff), "unsafe_networks") {
		t.Errorf("audit diff should name the field; got %s", diff)
	}
	if !strings.Contains(string(diff), "192.168.1.0/24") {
		t.Errorf("audit diff should record the new value; got %s", diff)
	}
}
