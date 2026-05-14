package models

import (
	"strings"
	"testing"
)

func TestFriendlyAddrError_DropsParseAddrText(t *testing.T) {
	got := FriendlyAddrError("nebula_ip", "10.42.0.22.333")
	if strings.Contains(got, "ParseAddr") {
		t.Errorf("message should not include the stdlib ParseAddr text; got %q", got)
	}
	if !strings.Contains(got, `"10.42.0.22.333"`) {
		t.Errorf("message should quote the offending value; got %q", got)
	}
	if !strings.Contains(got, "nebula_ip") {
		t.Errorf("message should include the field name; got %q", got)
	}
	if !strings.Contains(got, "not a valid IPv4 or IPv6 address") {
		t.Errorf("message should identify the constraint; got %q", got)
	}
}

func TestFriendlyAddrError_NoFieldOmitsPrefix(t *testing.T) {
	got := FriendlyAddrError("", "garbage")
	if strings.Contains(got, ":") {
		t.Errorf("unqualified message should not include a field/colon separator; got %q", got)
	}
}

func TestFriendlyPrefixError_StableShape(t *testing.T) {
	got := FriendlyPrefixError("cidr", "192.168.100.0/24/extra")
	if strings.Contains(got, "ParsePrefix") || strings.Contains(got, "netip:") {
		t.Errorf("message must not leak stdlib internals; got %q", got)
	}
	if !strings.Contains(got, "CIDR") {
		t.Errorf("message should identify the constraint; got %q", got)
	}
}

func TestValidateIPAddr_PropagatesFriendlyMessage(t *testing.T) {
	if _, err := ValidateIPAddr("public_ip", "10.0.0.999"); err == nil {
		t.Fatal("expected error")
	} else if strings.Contains(err.Error(), "ParseAddr") {
		t.Errorf("error must not contain ParseAddr text; got %v", err)
	}
	if _, err := ValidateIPAddr("public_ip", "203.0.113.10"); err != nil {
		t.Errorf("valid IP rejected: %v", err)
	}
}

func TestValidateCIDR_PropagatesFriendlyMessage(t *testing.T) {
	if _, err := ValidateCIDR("cidr", "not-a-cidr"); err == nil {
		t.Fatal("expected error")
	} else if strings.Contains(err.Error(), "ParsePrefix") {
		t.Errorf("error must not contain ParsePrefix text; got %v", err)
	}
	if _, err := ValidateCIDR("cidr", "192.168.0.0/24"); err != nil {
		t.Errorf("valid CIDR rejected: %v", err)
	}
}

func TestValidateHostAdvanced_FriendlyListenHost(t *testing.T) {
	err := ValidateHostAdvanced(&HostAdvanced{ListenHost: "not-an-ip"})
	if err == nil {
		t.Fatal("expected error for invalid listen_host")
	}
	if strings.Contains(err.Error(), "ParseAddr") {
		t.Errorf("listen_host error must not contain ParseAddr text; got %v", err)
	}
	if !strings.Contains(err.Error(), "advanced.listen_host") {
		t.Errorf("error should identify the field; got %v", err)
	}
}

func TestValidateHostAdvanced_FriendlyUnsafeRoutes(t *testing.T) {
	err := ValidateHostAdvanced(&HostAdvanced{
		UnsafeRoutes: []UnsafeRoute{{Route: "garbage", Via: "10.0.0.1"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid route CIDR")
	}
	if strings.Contains(err.Error(), "ParsePrefix") {
		t.Errorf("route error must not contain ParsePrefix text; got %v", err)
	}

	err = ValidateHostAdvanced(&HostAdvanced{
		UnsafeRoutes: []UnsafeRoute{{Route: "10.0.0.0/24", Via: "not-an-ip"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid via IP")
	}
	if strings.Contains(err.Error(), "ParseAddr") {
		t.Errorf("via error must not contain ParseAddr text; got %v", err)
	}
}

func TestValidateHostAdvanced_AcceptsValid(t *testing.T) {
	err := ValidateHostAdvanced(&HostAdvanced{
		ListenHost: "0.0.0.0",
		MTU:        1300,
		UnsafeRoutes: []UnsafeRoute{
			{Route: "192.168.10.0/24", Via: "10.0.0.99"},
		},
	})
	if err != nil {
		t.Errorf("valid HostAdvanced rejected: %v", err)
	}
}
