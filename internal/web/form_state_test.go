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

// TestNewOperatorFormState_ParsesFields parses form values from POST
// into operatorFormState with defaults for missing role field.
func TestNewOperatorFormState_ParsesFields(t *testing.T) {
	// Case 1: Full form with all fields
	form := url.Values{
		"username":     {"alice"},
		"display_name": {"Alice Smith"},
		"role":         {"admin"},
	}
	req := httptest.NewRequest("POST", "/ui/operators", nil)
	req.PostForm = form

	state := newOperatorFormState(req)

	if state.Username != "alice" {
		t.Errorf("Username = %q, want %q", state.Username, "alice")
	}
	if state.DisplayName != "Alice Smith" {
		t.Errorf("DisplayName = %q, want %q", state.DisplayName, "Alice Smith")
	}
	if state.Role != "admin" {
		t.Errorf("Role = %q, want %q", state.Role, "admin")
	}
	if state.Errors == nil {
		t.Errorf("Errors = nil, want non-nil empty map")
	}
	if len(state.Errors) != 0 {
		t.Errorf("len(Errors) = %d, want 0; got %v", len(state.Errors), state.Errors)
	}

	// Case 2: Missing role defaults to "user"
	form2 := url.Values{
		"username":     {"bob"},
		"display_name": {"Bob"},
	}
	req2 := httptest.NewRequest("POST", "/ui/operators", nil)
	req2.PostForm = form2

	state2 := newOperatorFormState(req2)

	if state2.Role != "user" {
		t.Errorf("Role (missing) = %q, want %q", state2.Role, "user")
	}

	// Case 3: Empty form yields empty struct with initialized Errors map
	form3 := url.Values{}
	req3 := httptest.NewRequest("POST", "/ui/operators", nil)
	req3.PostForm = form3

	state3 := newOperatorFormState(req3)

	if state3.Username != "" {
		t.Errorf("Username (empty) = %q, want %q", state3.Username, "")
	}
	if state3.DisplayName != "" {
		t.Errorf("DisplayName (empty) = %q, want %q", state3.DisplayName, "")
	}
	if state3.Role != "user" {
		t.Errorf("Role (empty) = %q, want %q", state3.Role, "user")
	}
	if state3.Errors == nil {
		t.Errorf("Errors (empty) = nil, want non-nil empty map")
	}
}

// TestNewOperatorFormState_TrimSpaces verifies that constructor trims whitespace.
func TestNewOperatorFormState_TrimSpaces(t *testing.T) {
	form := url.Values{
		"username":     {"  alice  "},
		"display_name": {"\n Bob \t"},
		"role":         {"admin"},
	}
	req := httptest.NewRequest("POST", "/ui/operators", nil)
	req.PostForm = form

	state := newOperatorFormState(req)

	if state.Username != "alice" {
		t.Errorf("Username (with spaces) = %q, want %q", state.Username, "alice")
	}
	if state.DisplayName != "Bob" {
		t.Errorf("DisplayName (with spaces) = %q, want %q", state.DisplayName, "Bob")
	}
}
