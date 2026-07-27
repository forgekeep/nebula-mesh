package models

import "testing"

// TestCertIdentityChanged covers each certificate-bound field on its own, and
// pins the fields that must NOT trigger a re-issuance — a false positive there
// churns certificates across the fleet on every routine config edit.
func TestCertIdentityChanged(t *testing.T) {
	base := func() *Host {
		return &Host{
			Name:       "web-1",
			NebulaIPs:  []string{"10.0.0.1", "fd00::1"},
			Groups:     []string{"web", "prod"},
			Role:       HostRoleHost,
			PublicIP:   "203.0.113.1",
			ListenPort: 4242,
		}
	}

	tests := []struct {
		name   string
		mutate func(*Host)
		want   bool
	}{
		{"no change", func(*Host) {}, false},

		{"name changed", func(h *Host) { h.Name = "web-2" }, true},
		{"ip changed", func(h *Host) { h.NebulaIPs = []string{"10.0.0.9", "fd00::1"} }, true},
		{"ip added", func(h *Host) { h.NebulaIPs = append(h.NebulaIPs, "10.0.0.2") }, true},
		{"ip removed", func(h *Host) { h.NebulaIPs = h.NebulaIPs[:1] }, true},
		// Order is preserved into the certificate, so a reorder is a change.
		{"ips reordered", func(h *Host) { h.NebulaIPs = []string{"fd00::1", "10.0.0.1"} }, true},

		{"group added", func(h *Host) { h.Groups = append(h.Groups, "admin") }, true},
		{"group removed", func(h *Host) { h.Groups = h.Groups[:1] }, true},
		{"group renamed", func(h *Host) { h.Groups = []string{"web", "staging"} }, true},
		{"groups reordered", func(h *Host) { h.Groups = []string{"prod", "web"} }, true},
		{"all groups cleared", func(h *Host) { h.Groups = nil }, true},

		// Config-only fields: delivered on the next poll, no new cert.
		{"role changed", func(h *Host) { h.Role = HostRoleLighthouse }, false},
		{"public ip changed", func(h *Host) { h.PublicIP = "203.0.113.9" }, false},
		{"listen port changed", func(h *Host) { h.ListenPort = 4243 }, false},
		{"advanced changed", func(h *Host) { h.Advanced = &HostAdvanced{MTU: 1300} }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, after := base(), base()
			tt.mutate(after)
			if got := CertIdentityChanged(before, after); got != tt.want {
				t.Errorf("CertIdentityChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCertIdentityChanged_NilSides mirrors HostDiff's contract: a nil side
// reads as the zero Host rather than panicking.
func TestCertIdentityChanged_NilSides(t *testing.T) {
	populated := &Host{Name: "web-1", Groups: []string{"web"}}

	if !CertIdentityChanged(nil, populated) {
		t.Error("nil before vs a populated host should count as changed")
	}
	if !CertIdentityChanged(populated, nil) {
		t.Error("a populated host vs nil after should count as changed")
	}
	if CertIdentityChanged(nil, nil) {
		t.Error("two zero hosts should not count as changed")
	}
}

// TestCertIdentityChanged_EmptyVersusNilSlices: a host round-tripped through
// JSON or the store can come back with []string{} where it went in as nil.
// Treating that as a change would rekey hosts on every no-op write.
func TestCertIdentityChanged_EmptyVersusNilSlices(t *testing.T) {
	nilSlices := &Host{Name: "web-1"}
	emptySlices := &Host{Name: "web-1", NebulaIPs: []string{}, Groups: []string{}}

	if CertIdentityChanged(nilSlices, emptySlices) {
		t.Error("nil and empty slices describe the same certificate; want no change")
	}
}
