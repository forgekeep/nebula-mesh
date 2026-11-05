package models

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestValidateHostAdvanced_ExtraEndpoints(t *testing.T) {
	valid := [][]string{
		{"192.168.1.10:4242"},
		{"192.168.1.10:4242", "192.168.1.10:4243", "[2001:db8::10]:4242"},
	}
	for _, endpoints := range valid {
		if err := ValidateHostAdvanced(&HostAdvanced{ExtraEndpoints: endpoints}); err != nil {
			t.Errorf("%v: unexpected error %v", endpoints, err)
		}
	}

	tooMany := make([]string, MaxExtraEndpoints+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("192.168.1.%d:4242", i+1)
	}
	invalid := []struct {
		endpoints []string
		want      string
	}{
		{[]string{"192.168.1.10"}, "must be IP:PORT"},
		{[]string{"lighthouse.lan:4242"}, "must be IP:PORT"},
		{[]string{"2001:db8::10:4242"}, "must be IP:PORT"},
		{[]string{"192.168.1.10:4242\nlighthouse: {}"}, "must be IP:PORT"},
		{[]string{"[fe80::1%eth0]:4242"}, "must not carry an IPv6 zone"},
		{[]string{"192.168.1.10:0"}, "needs a port"},
		{[]string{"0.0.0.0:4242"}, "not an address peers can dial"},
		{[]string{"127.0.0.1:4242"}, "not an address peers can dial"},
		{[]string{"[ff02::1]:4242"}, "not an address peers can dial"},
		{[]string{"[2001:db8::10]:4242", "[2001:DB8::10]:4242"}, "listed twice"},
		// IPv4-mapped IPv6 is normalized, as mesh import does, so the same
		// address in two spellings is still one endpoint.
		{[]string{"192.168.1.10:4242", "[::ffff:192.168.1.10]:4242"}, "listed twice"},
		{[]string{"[::ffff:127.0.0.1]:4242"}, "not an address peers can dial"},
		{[]string{"[fe80::1]:4242"}, "not an address peers can dial"},
		{tooMany, "at most 8 endpoints"},
	}
	for _, tt := range invalid {
		err := ValidateHostAdvanced(&HostAdvanced{ExtraEndpoints: tt.endpoints})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%q: got %v, want error containing %q", tt.endpoints, err, tt.want)
		}
	}
}

// TestValidateRoleReachability_ExtraEndpoints: extra endpoints are part of
// what peers dial, so reachability owns their role and public-endpoint checks.
func TestValidateRoleReachability_ExtraEndpoints(t *testing.T) {
	adv := &HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242"}}
	for _, role := range []HostRole{HostRoleLighthouse, HostRoleLighthouseRelay} {
		if err := ValidateRoleReachability(role, "203.0.113.10", 4242, adv); err != nil {
			t.Errorf("%s: unexpected error %v", role, err)
		}
	}
	// A plain host carries no public endpoint at all, and a relay has one:
	// both are refused before any reachability check, demotion included.
	for _, role := range []HostRole{HostRoleHost, HostRoleRelay} {
		if err := ValidateRoleReachability(role, "203.0.113.10", 4242, adv); !errors.Is(err, ErrExtraEndpointsRequireLighthouse) {
			t.Errorf("%s: got %v, want ErrExtraEndpointsRequireLighthouse", role, err)
		}
	}
	if err := ValidateRoleReachability(HostRoleHost, "", 0, &HostAdvanced{}); err != nil {
		t.Errorf("empty list on a plain host: unexpected error %v", err)
	}
	if err := ValidateRoleReachability(HostRoleRelay, "203.0.113.10", 4242, &HostAdvanced{MTU: 1300}); err != nil {
		t.Errorf("relay without extra endpoints: unexpected error %v", err)
	}
	if err := ValidateRoleReachability(HostRoleLighthouse, "", 4242, adv); !errors.Is(err, ErrRoleRequiresPublicIP) {
		t.Errorf("lighthouse without public_ip: got %v, want ErrRoleRequiresPublicIP", err)
	}

	public := &HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242", "203.0.113.10:4242"}}
	err := ValidateRoleReachability(HostRoleLighthouse, "203.0.113.10", 4242, public)
	if err == nil || !strings.Contains(err.Error(), "extra_endpoints[1]") {
		t.Errorf("public endpoint repeated: got %v", err)
	}
	mapped := &HostAdvanced{ExtraEndpoints: []string{"[::ffff:203.0.113.10]:4242"}}
	if err := ValidateRoleReachability(HostRoleLighthouse, "203.0.113.10", 4242, mapped); err == nil {
		t.Error("public endpoint repeated in IPv4-mapped form: accepted")
	}
	// listen_port is compared as an int: narrowing 70000 to uint16 would wrap
	// to 4464 and report a repeat that is not there.
	wrapped := &HostAdvanced{ExtraEndpoints: []string{"203.0.113.10:4464"}}
	if err := ValidateRoleReachability(HostRoleLighthouse, "203.0.113.10", 70000, wrapped); err != nil {
		t.Errorf("out-of-range listen_port wrapped onto an extra endpoint: %v", err)
	}
	if err := ValidateRoleReachability(HostRoleLighthouse, "203.0.113.10", 4243, public); err != nil {
		t.Errorf("same address on another port is a distinct endpoint: %v", err)
	}
}

func TestHostLighthouseEndpoints(t *testing.T) {
	lighthouse := &Host{
		IsLighthouse: true, NebulaIPs: []string{"10.0.0.1"},
		PublicIP: "2001:db8::1", ListenPort: 0,
		Advanced: &HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242"}},
	}
	want := []string{"[2001:db8::1]:4242", "192.168.1.10:4242"}
	if got := lighthouse.LighthouseEndpoints(); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	for name, h := range map[string]*Host{
		"nil":            nil,
		"not lighthouse": {NebulaIPs: []string{"10.0.0.2"}, PublicIP: "203.0.113.2"},
		"no public ip":   {IsLighthouse: true, NebulaIPs: []string{"10.0.0.3"}},
		"no nebula ip":   {IsLighthouse: true, PublicIP: "203.0.113.4"},
	} {
		if got := h.LighthouseEndpoints(); got != nil {
			t.Errorf("%s: got %v, want nil", name, got)
		}
	}
}

func TestHostDiff_ExtraEndpoints(t *testing.T) {
	before := &Host{Advanced: &HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242"}}}
	after := &Host{Advanced: &HostAdvanced{ExtraEndpoints: []string{"192.168.1.11:4242"}}}
	diff, changed, err := HostDiff(before, after)
	if err != nil || !changed || !strings.Contains(string(diff), `"advanced.extra_endpoints"`) {
		t.Fatalf("diff=%s changed=%v err=%v", diff, changed, err)
	}
	if _, changed, _ := HostDiff(before, &Host{Advanced: &HostAdvanced{ExtraEndpoints: []string{"192.168.1.10:4242"}}}); changed {
		t.Error("an identical list must not count as a change")
	}
}
