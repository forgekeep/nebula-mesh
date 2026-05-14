package web

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestNewNetworkFormState_ParsesArrayCIDRs parses multiple CIDR values
// from POST form cidrs[] fields into Form.CIDRs slice.
func TestNewNetworkFormState_ParsesArrayCIDRs(t *testing.T) {
	form := url.Values{
		"name":   {"dual-stack"},
		"cidrs":  {"10.42.0.0/24", "fd00:42::/64"},
		"ca_id":  {"ca-1"},
	}
	req := httptest.NewRequest("POST", "/ui/networks", nil)
	req.PostForm = form

	state := newNetworkFormState(req)

	if state.Name != "dual-stack" {
		t.Errorf("Name = %q, want %q", state.Name, "dual-stack")
	}
	if len(state.CIDRs) != 2 {
		t.Errorf("len(CIDRs) = %d, want 2; got %v", len(state.CIDRs), state.CIDRs)
	}
	if state.CIDRs[0] != "10.42.0.0/24" {
		t.Errorf("CIDRs[0] = %q, want %q", state.CIDRs[0], "10.42.0.0/24")
	}
	if state.CIDRs[1] != "fd00:42::/64" {
		t.Errorf("CIDRs[1] = %q, want %q", state.CIDRs[1], "fd00:42::/64")
	}
	if state.CAID != "ca-1" {
		t.Errorf("CAID = %q, want %q", state.CAID, "ca-1")
	}
}

// TestNewNetworkFormState_TrimsEmpty removes empty CIDR entries from the slice.
func TestNewNetworkFormState_TrimsEmpty(t *testing.T) {
	form := url.Values{
		"name":  {"net"},
		"cidrs": {"10.0.0.0/24", "", "fd00::/64", ""},
	}
	req := httptest.NewRequest("POST", "/ui/networks", nil)
	req.PostForm = form

	state := newNetworkFormState(req)

	if len(state.CIDRs) != 2 {
		t.Errorf("len(CIDRs) = %d, want 2; got %v", len(state.CIDRs), state.CIDRs)
	}
	if state.CIDRs[0] != "10.0.0.0/24" {
		t.Errorf("CIDRs[0] = %q, want %q", state.CIDRs[0], "10.0.0.0/24")
	}
	if state.CIDRs[1] != "fd00::/64" {
		t.Errorf("CIDRs[1] = %q, want %q", state.CIDRs[1], "fd00::/64")
	}
}

// TestNewHostFormState_ParsesArrayNebulaIPs parses multiple IP values
// from POST form nebula_ips[] fields into Form.NebulaIPs slice.
func TestNewHostFormState_ParsesArrayNebulaIPs(t *testing.T) {
	form := url.Values{
		"network_id": {"net-1"},
		"name":       {"host-1"},
		"nebula_ips": {"10.42.0.10", "fd00::10"},
		"role":       {"host"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", nil)
	req.PostForm = form

	state := newHostFormState(req)

	if state.NetworkID != "net-1" {
		t.Errorf("NetworkID = %q, want %q", state.NetworkID, "net-1")
	}
	if state.Name != "host-1" {
		t.Errorf("Name = %q, want %q", state.Name, "host-1")
	}
	if len(state.NebulaIPs) != 2 {
		t.Errorf("len(NebulaIPs) = %d, want 2; got %v", len(state.NebulaIPs), state.NebulaIPs)
	}
	if state.NebulaIPs[0] != "10.42.0.10" {
		t.Errorf("NebulaIPs[0] = %q, want %q", state.NebulaIPs[0], "10.42.0.10")
	}
	if state.NebulaIPs[1] != "fd00::10" {
		t.Errorf("NebulaIPs[1] = %q, want %q", state.NebulaIPs[1], "fd00::10")
	}
	if state.Role != "host" {
		t.Errorf("Role = %q, want %q", state.Role, "host")
	}
}

// TestNewHostFormState_TrimsEmptyNebulaIPs removes empty IP entries from the slice.
func TestNewHostFormState_TrimsEmptyNebulaIPs(t *testing.T) {
	form := url.Values{
		"network_id": {"net-1"},
		"name":       {"host-1"},
		"nebula_ips": {"10.42.0.10", "", "fd00::10", ""},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", nil)
	req.PostForm = form

	state := newHostFormState(req)

	if len(state.NebulaIPs) != 2 {
		t.Errorf("len(NebulaIPs) = %d, want 2; got %v", len(state.NebulaIPs), state.NebulaIPs)
	}
	if state.NebulaIPs[0] != "10.42.0.10" {
		t.Errorf("NebulaIPs[0] = %q, want %q", state.NebulaIPs[0], "10.42.0.10")
	}
	if state.NebulaIPs[1] != "fd00::10" {
		t.Errorf("NebulaIPs[1] = %q, want %q", state.NebulaIPs[1], "fd00::10")
	}
}
