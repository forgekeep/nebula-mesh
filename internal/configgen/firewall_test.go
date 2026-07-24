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
