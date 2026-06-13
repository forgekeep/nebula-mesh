package configgen

import "testing"

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
