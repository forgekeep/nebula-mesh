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
		return
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
		return
	}
	if strings.Contains(err.Error(), "ParsePrefix") {
		t.Errorf("route error must not contain ParsePrefix text; got %v", err)
	}

	err = ValidateHostAdvanced(&HostAdvanced{
		UnsafeRoutes: []UnsafeRoute{{Route: "10.0.0.0/24", Via: "not-an-ip"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid via IP")
		return
	}
	if strings.Contains(err.Error(), "ParseAddr") {
		t.Errorf("via error must not contain ParseAddr text; got %v", err)
	}
}

func TestValidateHostAdvanced_AcceptsValid(t *testing.T) {
	err := ValidateHostAdvanced(&HostAdvanced{
		ListenHost: "0.0.0.0",
		MTU:        1300,
		TunDevice:  "nebula1",
		UnsafeRoutes: []UnsafeRoute{
			{Route: "192.168.10.0/24", Via: "10.0.0.99"},
		},
	})
	if err != nil {
		t.Errorf("valid HostAdvanced rejected: %v", err)
	}
}

// TestValidateHostAdvanced_TunDeviceInjection covers GHSA-7hp6-g3pq-3pc3:
// the TunDevice value is interpolated raw into the agent config.yml via
// text/template, so any byte that a YAML parser treats as a line
// terminator can inject sibling keys (am_lighthouse, am_relay, …).
// The previous denylist rejected " \t\n/" but missed \r (CR — accepted
// by go-yaml v3 and most YAML 1.1 parsers as a line break) and Unicode
// line separators NEL/LS/PS. The whitelist regex closes both bypasses
// and additionally caps length at the Linux IFNAMSIZ-1 (15 bytes).
func TestValidateHostAdvanced_TunDeviceInjection(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"cr_injection", "nebula0\rlighthouse: {am_lighthouse: true}"},
		{"unicode_nel", "nebula0\u0085injected"},
		{"unicode_ls", "nebula0\u2028injected"},
		{"unicode_ps", "nebula0\u2029injected"},
		{"yaml_flow_mapping", "nebula0,am_lighthouse:true"},
		{"yaml_inline_quote", `nebula0"`},
		{"yaml_comment", "nebula0#injected"},
		{"yaml_anchor", "&anchor"},
		{"yaml_alias", "*alias"},
		{"colon_separator", "tun:value"},
		{"open_brace", "nebula{"},
		{"open_bracket", "nebula["},
		{"too_long_16", "0123456789abcdef"},      // 16 chars > IFNAMSIZ-1
		{"too_long_32", strings.Repeat("a", 32)}, // previous limit
		{"original_space", "nebula 0"},
		{"original_tab", "nebula\t0"},
		{"original_newline", "nebula\n0"},
		{"original_slash", "nebula/0"},
		{"empty_via_only_whitespace", " "}, // becomes non-empty after TrimSpace upstream is bypassed
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateHostAdvanced(&HostAdvanced{TunDevice: c.in})
			if err == nil {
				t.Errorf("ValidateHostAdvanced accepted dangerous TunDevice %q", c.in)
			}
		})
	}
}

func TestValidateHostAdvanced_TunDeviceAccepts(t *testing.T) {
	cases := []string{
		"nebula0",
		"nebula1",
		"tun-0",
		"tun_test",
		"A",
		"012345678901234", // exactly 15
		"-_",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			err := ValidateHostAdvanced(&HostAdvanced{TunDevice: in})
			if err != nil {
				t.Errorf("ValidateHostAdvanced rejected valid TunDevice %q: %v", in, err)
			}
		})
	}
}
