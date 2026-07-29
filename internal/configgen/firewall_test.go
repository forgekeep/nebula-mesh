package configgen

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestFirewallRulesFromJSON(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		wantErr     bool
		wantInbound []FirewallRule
		wantOutLen  int
	}{
		{
			name:        "empty string -> defaults, no error",
			json:        "",
			wantInbound: DefaultFirewallInbound,
			wantOutLen:  len(DefaultFirewallOutbound),
		},
		{
			name:        "both empty arrays -> defaults, no error",
			json:        `{"inbound":[],"outbound":[]}`,
			wantInbound: DefaultFirewallInbound,
			wantOutLen:  len(DefaultFirewallOutbound),
		},
		{
			name:        "valid rules applied verbatim",
			json:        `{"inbound":[{"port":"443","proto":"tcp","group":"web"}],"outbound":[{"port":"any","proto":"any","group":"any"}]}`,
			wantInbound: []FirewallRule{{Port: "443", Proto: "tcp", Group: "web"}},
			wantOutLen:  1,
		},
		{
			name:        "inbound rules with empty outbound rendered faithfully",
			json:        `{"inbound":[{"port":"22","proto":"tcp","group":"admin"}],"outbound":[]}`,
			wantInbound: []FirewallRule{{Port: "22", Proto: "tcp", Group: "admin"}},
			wantOutLen:  0,
		},
		{
			name:        "malformed JSON -> defaults + error",
			json:        `{not json`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
			wantOutLen:  len(DefaultFirewallOutbound),
		},
		{
			name:        "empty group (work-322fy footgun) -> defaults + error",
			json:        `{"inbound":[{"port":"22","proto":"tcp","group":""}],"outbound":[]}`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
			wantOutLen:  len(DefaultFirewallOutbound),
		},
		{
			name:        "empty port -> defaults + error",
			json:        `{"inbound":[],"outbound":[{"port":"","proto":"any","group":"any"}]}`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
			wantOutLen:  len(DefaultFirewallOutbound),
		},
		{
			name:        "empty proto -> defaults + error",
			json:        `{"inbound":[{"port":"22","proto":"","group":"admin"}],"outbound":[]}`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
			wantOutLen:  len(DefaultFirewallOutbound),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, out, err := FirewallRulesFromJSON(tc.json)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(in) != len(tc.wantInbound) {
				t.Fatalf("inbound len = %d, want %d", len(in), len(tc.wantInbound))
			}
			for i := range tc.wantInbound {
				if in[i] != tc.wantInbound[i] {
					t.Errorf("inbound[%d] = %+v, want %+v", i, in[i], tc.wantInbound[i])
				}
			}
			if len(out) != tc.wantOutLen {
				t.Errorf("outbound len = %d, want %d", len(out), tc.wantOutLen)
			}
		})
	}
}

// TestFirewallRulesFromJSON_DefaultsAreLoadable guards that the baseline the
// fallback returns actually renders into a Nebula-loadable config (no empty
// group/host), so the "fall back to default on bad input" safety net can't
// itself produce a broken config.
func TestFirewallRulesFromJSON_DefaultsRenderValidRules(t *testing.T) {
	in, out, err := FirewallRulesFromJSON(`{"inbound":[{"port":"x","proto":"y","group":""}]}`)
	if err == nil {
		t.Fatal("expected error for empty-group rule")
	}
	mapped := mapFirewallRules(in)
	mapped = append(mapped, mapFirewallRules(out)...)
	for _, r := range mapped {
		if r.Group == "" && r.Host == "" {
			t.Errorf("default rule has neither group nor host (Nebula would reject): %+v", r)
		}
	}
}

func TestGenerate_HostFirewallInboundAppended(t *testing.T) {
	input := GeneratorInput{
		HostName:   "bastion",
		NebulaIPs:  []string{"192.168.100.5"},
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		HostFirewallInbound: []FirewallRule{
			{Port: "22", Proto: "tcp", Group: "admin"},
			{Port: "8000-9000", Proto: "udp", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var parsed struct {
		Firewall struct {
			Inbound  []map[string]any `yaml:"inbound"`
			Outbound []map[string]any `yaml:"outbound"`
		} `yaml:"firewall"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	in := parsed.Firewall.Inbound
	if len(in) != 3 {
		t.Fatalf("inbound rules = %d, want 3 (network first, then host): %s", len(in), string(data))
	}
	// Network rule first.
	if in[0]["proto"] != "icmp" || in[0]["host"] != "any" {
		t.Errorf("inbound[0] should be the network icmp/any rule, got %v", in[0])
	}
	// Host rules appended in order.
	if in[1]["port"] != 22 && in[1]["port"] != "22" {
		t.Errorf("inbound[1].port = %v, want 22", in[1]["port"])
	}
	if in[1]["group"] != "admin" {
		t.Errorf("inbound[1].group = %v, want admin", in[1]["group"])
	}
	// Host rule with group "any" renders as host: any (mapFirewallRules).
	if in[2]["host"] != "any" {
		t.Errorf("inbound[2] group any should render host: any, got %v", in[2])
	}
	if len(parsed.Firewall.Outbound) != 1 {
		t.Errorf("outbound rules = %d, want 1 (untouched)", len(parsed.Firewall.Outbound))
	}
}

func TestGenerate_HostFirewallInbound_DoesNotMutateDefaults(t *testing.T) {
	input := GeneratorInput{
		HostName:         "h",
		NebulaIPs:        []string{"192.168.100.6"},
		CACertPath:       "/etc/nebula/ca.crt",
		CertPath:         "/etc/nebula/host.crt",
		KeyPath:          "/etc/nebula/host.key",
		FirewallInbound:  DefaultFirewallInbound,
		FirewallOutbound: DefaultFirewallOutbound,
		HostFirewallInbound: []FirewallRule{
			{Port: "22", Proto: "tcp", Group: "admin"},
		},
	}
	if _, err := Generate(input); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(DefaultFirewallInbound) != 1 {
		t.Fatalf("DefaultFirewallInbound mutated: %#v", DefaultFirewallInbound)
	}
}

// TestFirewallRulesFromJSON_CIDRFields covers the cidr / local_cidr rule
// fields: accepted forms round-trip verbatim, and the combinations Nebula
// would either reject or silently widen fall back to the baseline.
func TestFirewallRulesFromJSON_CIDRFields(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		wantErr     bool
		wantInbound []FirewallRule
	}{
		{
			name:        "cidr selects the peer without a group",
			json:        `{"inbound":[{"port":"443","proto":"tcp","cidr":"10.0.0.0/24"}],"outbound":[]}`,
			wantInbound: []FirewallRule{{Port: "443", Proto: "tcp", Cidr: "10.0.0.0/24"}},
		},
		{
			name:        "local_cidr accompanies a group",
			json:        `{"inbound":[{"port":"any","proto":"any","group":"web","local_cidr":"172.16.0.0/16"}],"outbound":[]}`,
			wantInbound: []FirewallRule{{Port: "any", Proto: "any", Group: "web", LocalCidr: "172.16.0.0/16"}},
		},
		{
			name:        "any is a valid cidr and local_cidr value",
			json:        `{"inbound":[{"port":"any","proto":"any","cidr":"any","local_cidr":"any"}],"outbound":[]}`,
			wantInbound: []FirewallRule{{Port: "any", Proto: "any", Cidr: "any", LocalCidr: "any"}},
		},
		{
			name:        "ipv6 prefixes accepted",
			json:        `{"inbound":[{"port":"any","proto":"any","cidr":"fd00::/8","local_cidr":"::/0"}],"outbound":[]}`,
			wantInbound: []FirewallRule{{Port: "any", Proto: "any", Cidr: "fd00::/8", LocalCidr: "::/0"}},
		},
		{
			// Nebula OR's group and cidr, so a rule with both is wider than
			// either alone — refuse rather than render the wider rule.
			name:        "group and cidr together -> defaults + error",
			json:        `{"inbound":[{"port":"443","proto":"tcp","group":"web","cidr":"10.0.0.0/24"}],"outbound":[]}`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
		},
		{
			name:        "no group and no cidr -> defaults + error",
			json:        `{"inbound":[{"port":"443","proto":"tcp","local_cidr":"10.0.0.0/24"}],"outbound":[]}`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
		},
		{
			name:        "unparseable cidr -> defaults + error",
			json:        `{"inbound":[{"port":"443","proto":"tcp","cidr":"10.0.0.0/33"}],"outbound":[]}`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
		},
		{
			name:        "bare IP is not a cidr -> defaults + error",
			json:        `{"inbound":[{"port":"443","proto":"tcp","cidr":"10.0.0.1"}],"outbound":[]}`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
		},
		{
			name:        "unparseable local_cidr -> defaults + error",
			json:        `{"outbound":[{"port":"any","proto":"any","group":"any","local_cidr":"nope"}],"inbound":[]}`,
			wantErr:     true,
			wantInbound: DefaultFirewallInbound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, _, err := FirewallRulesFromJSON(tc.json)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if len(in) != len(tc.wantInbound) {
				t.Fatalf("inbound = %+v, want %+v", in, tc.wantInbound)
			}
			for i := range tc.wantInbound {
				if in[i] != tc.wantInbound[i] {
					t.Errorf("inbound[%d] = %+v, want %+v", i, in[i], tc.wantInbound[i])
				}
			}
		})
	}
}

// TestGenerate_FirewallCIDRRendering pins the YAML shape of cidr / local_cidr
// rules. The critical property is that a cidr-selected rule emits neither
// `host` nor `group`: Nebula OR's the peer selectors, so a stray `host: any`
// alongside `cidr` would match every peer and discard the restriction.
func TestGenerate_FirewallCIDRRendering(t *testing.T) {
	input := GeneratorInput{
		HostName:   "gw",
		NebulaIPs:  []string{"192.168.100.7"},
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
		FirewallInbound: []FirewallRule{
			{Port: "443", Proto: "tcp", Cidr: "10.0.0.0/24"},
			{Port: "22", Proto: "tcp", Group: "admin", LocalCidr: "192.168.50.0/24"},
			{Port: "any", Proto: "icmp", Group: "any", LocalCidr: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Cidr: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var parsed struct {
		Firewall struct {
			Inbound  []map[string]any `yaml:"inbound"`
			Outbound []map[string]any `yaml:"outbound"`
		} `yaml:"firewall"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	in := parsed.Firewall.Inbound
	if len(in) != 3 {
		t.Fatalf("inbound rules = %d, want 3: %s", len(in), string(data))
	}

	// cidr-selected rule: cidr only, no host/group, no local_cidr key.
	if in[0]["cidr"] != "10.0.0.0/24" {
		t.Errorf("inbound[0].cidr = %v, want 10.0.0.0/24", in[0]["cidr"])
	}
	if _, ok := in[0]["host"]; ok {
		t.Errorf("inbound[0] must not emit host alongside cidr (Nebula OR's them, matching every peer): %v", in[0])
	}
	if _, ok := in[0]["group"]; ok {
		t.Errorf("inbound[0] must not emit group alongside cidr: %v", in[0])
	}
	if _, ok := in[0]["local_cidr"]; ok {
		t.Errorf("inbound[0] should omit an unset local_cidr: %v", in[0])
	}

	// group + local_cidr: both emitted, AND'd by Nebula.
	if in[1]["group"] != "admin" || in[1]["local_cidr"] != "192.168.50.0/24" {
		t.Errorf("inbound[1] = %v, want group admin with local_cidr 192.168.50.0/24", in[1])
	}
	if _, ok := in[1]["cidr"]; ok {
		t.Errorf("inbound[1] should omit an unset cidr: %v", in[1])
	}

	// group "any" still renders host: any, now with local_cidr alongside.
	if in[2]["host"] != "any" || in[2]["local_cidr"] != "any" {
		t.Errorf("inbound[2] = %v, want host any with local_cidr any", in[2])
	}

	out := parsed.Firewall.Outbound
	if len(out) != 1 {
		t.Fatalf("outbound rules = %d, want 1", len(out))
	}
	if out[0]["cidr"] != "any" {
		t.Errorf("outbound[0].cidr = %v, want any", out[0]["cidr"])
	}
	if _, ok := out[0]["host"]; ok {
		t.Errorf("outbound[0] must not emit host alongside cidr: %v", out[0])
	}
}

// TestGenerate_FirewallIPv6CIDRSurvivesYAML guards the YAML scalar safety of
// IPv6 prefixes. "::/0" starts with a colon, an indicator character, so it is
// exactly the kind of value a plain scalar can mangle — if it ever emitted
// unquoted in a way the loader retyped, agents would fail to load the config or
// silently match a different prefix. safeString's "!!str" tag is what makes it
// safe; this test fails if that changes.
func TestGenerate_FirewallIPv6CIDRSurvivesYAML(t *testing.T) {
	input := GeneratorInput{
		HostName:   "v6",
		NebulaIPs:  []string{"fd00::1"},
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "any", Cidr: "::/0", LocalCidr: "::/0"},
			{Port: "any", Proto: "any", Cidr: "fd00::/8", LocalCidr: "fe80::/10"},
		},
		FirewallOutbound: []FirewallRule{{Port: "any", Proto: "any", Group: "any"}},
	}
	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var parsed struct {
		Firewall struct {
			Inbound []map[string]any `yaml:"inbound"`
		} `yaml:"firewall"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("IPv6 firewall prefixes broke the config's YAML: %v\n%s", err, data)
	}
	want := []struct{ cidr, localCidr string }{
		{"::/0", "::/0"},
		{"fd00::/8", "fe80::/10"},
	}
	if len(parsed.Firewall.Inbound) != len(want) {
		t.Fatalf("inbound rules = %d, want %d\n%s", len(parsed.Firewall.Inbound), len(want), data)
	}
	for i, w := range want {
		if got := parsed.Firewall.Inbound[i]["cidr"]; got != w.cidr {
			t.Errorf("inbound[%d].cidr = %#v (%T), want %q as a string", i, got, got, w.cidr)
		}
		if got := parsed.Firewall.Inbound[i]["local_cidr"]; got != w.localCidr {
			t.Errorf("inbound[%d].local_cidr = %#v (%T), want %q as a string", i, got, got, w.localCidr)
		}
	}
}
