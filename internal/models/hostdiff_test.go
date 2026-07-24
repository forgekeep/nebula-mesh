package models

import (
	"encoding/json"
	"testing"
)

// TestHostDiff_NoChanges verifies that identical hosts produce no diff.
func TestHostDiff_NoChanges(t *testing.T) {
	before := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced:   nil,
	}
	after := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced:   nil,
	}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff failed: %v", err)
	}
	if hasChanges {
		t.Fatalf("expected hasChanges=false, got true")
	}
	if diff != nil {
		t.Fatalf("expected nil diff, got %q", string(diff))
	}
}

// TestHostDiff_NameChanged verifies that name change is captured in diff.
func TestHostDiff_NameChanged(t *testing.T) {
	before := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced:   nil,
	}
	after := &Host{
		Name:       "web-2",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced:   nil,
	}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff failed: %v", err)
	}
	if !hasChanges {
		t.Fatalf("expected hasChanges=true, got false")
	}

	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatalf("failed to unmarshal diff JSON: %v", err)
	}

	// Should contain only "name" key
	if len(result) != 1 {
		t.Fatalf("expected 1 changed field, got %d: %+v", len(result), result)
	}
	if _, ok := result["name"]; !ok {
		t.Fatalf("expected 'name' in diff, got keys: %v", result)
	}

	nameChange := result["name"]
	if beforeVal, ok := nameChange["before"]; !ok || beforeVal != "web-1" {
		t.Fatalf("expected before='web-1', got %v", nameChange)
	}
	if afterVal, ok := nameChange["after"]; !ok || afterVal != "web-2" {
		t.Fatalf("expected after='web-2', got %v", nameChange)
	}
}

// TestHostDiff_AdvancedMTUChanged verifies advanced.mtu change in diff.
func TestHostDiff_AdvancedMTUChanged(t *testing.T) {
	before := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced: &HostAdvanced{
			MTU: 1300,
		},
	}
	after := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced: &HostAdvanced{
			MTU: 1280,
		},
	}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff failed: %v", err)
	}
	if !hasChanges {
		t.Fatalf("expected hasChanges=true")
	}

	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatalf("failed to unmarshal diff JSON: %v", err)
	}

	if _, ok := result["advanced.mtu"]; !ok {
		t.Fatalf("expected 'advanced.mtu' in diff, got keys: %v", result)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 changed field, got %d: %+v", len(result), result)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 changed field, got %d: %+v", len(result), result)
	}
	mtuChange := result["advanced.mtu"]
	if mtuChange["before"] != 1300.0 && mtuChange["before"] != 1300 {
		t.Fatalf("expected before=1300, got %v (type %T)", mtuChange["before"], mtuChange["before"])
	}
	if mtuChange["after"] != 1280.0 && mtuChange["after"] != 1280 {
		t.Fatalf("expected after=1280, got %v (type %T)", mtuChange["after"], mtuChange["after"])
	}
}

// TestHostDiff_AdvancedNilToNonNil verifies transition from nil to non-nil Advanced.
func TestHostDiff_AdvancedNilToNonNil(t *testing.T) {
	before := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced:   nil,
	}
	after := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced: &HostAdvanced{
			MTU: 1300,
		},
	}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff failed: %v", err)
	}
	if !hasChanges {
		t.Fatalf("expected hasChanges=true")
	}

	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatalf("failed to unmarshal diff JSON: %v", err)
	}

	if _, ok := result["advanced.mtu"]; !ok {
		t.Fatalf("expected 'advanced.mtu' in diff, got keys: %v", result)
	}
	// Only one change since only MTU was set in Advanced
	if len(result) != 1 {
		t.Fatalf("expected 1 changed field, got %d: %+v", len(result), result)
	}
	mtuChange := result["advanced.mtu"]
	// Before should be 0 (zero value for nil Advanced)
	beforeVal := mtuChange["before"]
	afterVal := mtuChange["after"]
	if beforeVal != 0.0 && beforeVal != 0 {
		t.Fatalf("expected before=0 for nil Advanced, got %v (type %T)", beforeVal, beforeVal)
	}
	if afterVal != 1300.0 && afterVal != 1300 {
		t.Fatalf("expected after=1300, got %v (type %T)", afterVal, afterVal)
	}
}

// TestHostDiff_GroupsSliceChanged verifies that Groups slice rearrangement is captured.
func TestHostDiff_GroupsSliceChanged(t *testing.T) {
	before := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web", "prod"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced:   nil,
	}
	after := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web", "staging"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced:   nil,
	}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff failed: %v", err)
	}
	if !hasChanges {
		t.Fatalf("expected hasChanges=true")
	}

	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatalf("failed to unmarshal diff JSON: %v", err)
	}

	if _, ok := result["groups"]; !ok {
		t.Fatalf("expected 'groups' in diff, got keys: %v", result)
	}
	groupChange := result["groups"]
	if groupChange["before"] == nil || groupChange["after"] == nil {
		t.Fatalf("groups change malformed: %+v", groupChange)
	}
}

// TestHostDiff_DeterministicKeyOrder verifies that key order is deterministic.
func TestHostDiff_DeterministicKeyOrder(t *testing.T) {
	before := &Host{
		Name:       "web-1",
		NebulaIPs:  []string{"192.168.100.1"},
		Groups:     []string{"web"},
		Role:       HostRoleHost,
		PublicIP:   "203.0.113.1",
		ListenPort: 4242,
		Advanced: &HostAdvanced{
			MTU: 1300,
		},
	}
	after := &Host{
		Name:       "web-2",
		NebulaIPs:  []string{"192.168.100.99"},
		Groups:     []string{"web"},
		Role:       HostRoleLighthouse,
		PublicIP:   "203.0.113.2",
		ListenPort: 4343,
		Advanced: &HostAdvanced{
			MTU: 1280,
		},
	}

	// Run 10 times and verify output is identical
	var outputs []string
	for i := 0; i < 10; i++ {
		diff, _, err := HostDiff(before, after)
		if err != nil {
			t.Fatalf("HostDiff iteration %d failed: %v", i, err)
		}
		outputs = append(outputs, string(diff))
	}

	for i := 1; i < len(outputs); i++ {
		if outputs[i] != outputs[0] {
			t.Fatalf("iteration %d output differs from iteration 0\n%s\nvs\n%s", i, outputs[0], outputs[i])
		}
	}
}

// TestHostDiff_PunchyTriState verifies tri-state Punchy handling in Advanced.
func TestHostDiff_PunchyTriState(t *testing.T) {
	falseVal := false
	before := &Host{
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.1"},
		Groups:    []string{},
		Role:      HostRoleHost,
		Advanced: &HostAdvanced{
			Punchy: nil,
		},
	}
	after := &Host{
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.1"},
		Groups:    []string{},
		Role:      HostRoleHost,
		Advanced: &HostAdvanced{
			Punchy: &falseVal,
		},
	}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff failed: %v", err)
	}
	if !hasChanges {
		t.Fatalf("expected hasChanges=true")
	}

	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatalf("failed to unmarshal diff JSON: %v", err)
	}

	if _, ok := result["advanced.punchy"]; !ok {
		t.Fatalf("expected 'advanced.punchy' in diff, got keys: %v", result)
	}
	punchyChange := result["advanced.punchy"]
	// nil → false
	if got, _ := punchyChange["after"].(bool); got {
		t.Fatalf("expected after=false, got %v", punchyChange["after"])
	}
}

// TestHostDiff_MultipleAdvancedChanges verifies multiple Advanced subfields in one diff.
func TestHostDiff_MultipleAdvancedChanges(t *testing.T) {
	trueVal := true
	before := &Host{
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.1"},
		Groups:    []string{},
		Role:      HostRoleHost,
		Advanced: &HostAdvanced{
			MTU:    1300,
			Punchy: &trueVal,
		},
	}
	after := &Host{
		Name:      "web-1",
		NebulaIPs: []string{"192.168.100.1"},
		Groups:    []string{},
		Role:      HostRoleHost,
		Advanced: &HostAdvanced{
			MTU:    1280,
			Punchy: &trueVal,
		},
	}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff failed: %v", err)
	}
	if !hasChanges {
		t.Fatalf("expected hasChanges=true")
	}

	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatalf("failed to unmarshal diff JSON: %v", err)
	}

	// Should have exactly one changed field (MTU), Punchy unchanged
	if len(result) != 1 {
		t.Fatalf("expected 1 changed field, got %d: %+v", len(result), result)
	}
	if _, ok := result["advanced.mtu"]; !ok {
		t.Fatalf("expected 'advanced.mtu' in diff, got keys: %v", result)
	}
}

// TestHostDiff_RoleAndLighthouseFlags verifies role and lighthouse flag changes.
func TestHostDiff_RoleAndLighthouseFlags(t *testing.T) {
	before := &Host{
		Name:         "web-1",
		NebulaIPs:    []string{"192.168.100.1"},
		Groups:       []string{},
		Role:         HostRoleHost,
		IsLighthouse: false,
		PublicIP:     "203.0.113.1",
		ListenPort:   4242,
	}
	after := &Host{
		Name:         "web-1",
		NebulaIPs:    []string{"192.168.100.1"},
		Groups:       []string{},
		Role:         HostRoleLighthouse,
		IsLighthouse: true,
		PublicIP:     "203.0.113.1",
		ListenPort:   4242,
	}

	diff, hasChanges, err := HostDiff(before, after)
	if err != nil {
		t.Fatalf("HostDiff failed: %v", err)
	}
	if !hasChanges {
		t.Fatalf("expected hasChanges=true")
	}

	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatalf("failed to unmarshal diff JSON: %v", err)
	}

	if _, ok := result["role"]; !ok {
		t.Fatalf("expected 'role' in diff, got keys: %v", result)
	}
	roleChange := result["role"]
	if roleChange["before"] != "host" || roleChange["after"] != "lighthouse" {
		t.Fatalf("role change mismatch: %+v", roleChange)
	}
}

func TestHostDiff_AdvancedFirewallInbound(t *testing.T) {
	ruleA := HostFirewallRule{Port: "443", Proto: "tcp", Group: "web"}
	ruleB := HostFirewallRule{Port: "22", Proto: "tcp", Group: "admin"}

	cases := []struct {
		name       string
		before     *HostAdvanced
		after      *HostAdvanced
		wantChange bool
	}{
		{"add rule to nil advanced", nil, &HostAdvanced{FirewallInbound: []HostFirewallRule{ruleA}}, true},
		{"remove all rules", &HostAdvanced{FirewallInbound: []HostFirewallRule{ruleA}}, &HostAdvanced{}, true},
		{"change rule", &HostAdvanced{FirewallInbound: []HostFirewallRule{ruleA}}, &HostAdvanced{FirewallInbound: []HostFirewallRule{ruleB}}, true},
		{"reorder rules", &HostAdvanced{FirewallInbound: []HostFirewallRule{ruleA, ruleB}}, &HostAdvanced{FirewallInbound: []HostFirewallRule{ruleB, ruleA}}, true},
		{"identical rules", &HostAdvanced{FirewallInbound: []HostFirewallRule{ruleA}}, &HostAdvanced{FirewallInbound: []HostFirewallRule{ruleA}}, false},
		{"both empty", &HostAdvanced{}, &HostAdvanced{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := &Host{Name: "h", Advanced: tc.before}
			after := &Host{Name: "h", Advanced: tc.after}
			diffJSON, hasChanges, err := HostDiff(before, after)
			if err != nil {
				t.Fatal(err)
			}
			if hasChanges != tc.wantChange {
				t.Fatalf("hasChanges = %v, want %v (diff: %s)", hasChanges, tc.wantChange, diffJSON)
			}
			if !tc.wantChange {
				return
			}
			var parsed map[string]map[string]any
			if err := json.Unmarshal(diffJSON, &parsed); err != nil {
				t.Fatalf("unmarshal diff: %v", err)
			}
			if _, ok := parsed["advanced.firewall_inbound"]; !ok {
				t.Errorf("diff missing key advanced.firewall_inbound: %s", diffJSON)
			}
		})
	}
}
