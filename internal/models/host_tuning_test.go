package models

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateHostAdvanced_Tuning(t *testing.T) {
	yes := true
	valid := []HostAdvanced{
		{Routines: 1},
		{Routines: MaxRoutines},
		{Routines: 4, PinThreads: &yes, PinThreadsKey: "pid", CPUAffinity: []int{0, MaxCPUIndex}},
		{UDPOffloads: &yes, TunOffloads: &yes},
		{LocalAPIControlEnabled: &yes, LocalAPIControlGroup: `CORP\Nebula Admins`},
	}
	for i, adv := range valid {
		if err := ValidateHostAdvanced(&adv); err != nil {
			t.Errorf("valid[%d]: %v", i, err)
		}
	}
	invalid := []struct {
		adv  HostAdvanced
		want string
	}{
		{HostAdvanced{Routines: -1}, "advanced.routines must be between 1 and 64"},
		{HostAdvanced{Routines: MaxRoutines + 1}, "advanced.routines must be between 1 and 64"},
		{HostAdvanced{PinThreads: &yes}, "need advanced.routines above 1"},
		{HostAdvanced{Routines: 1, CPUAffinity: []int{0}}, "need advanced.routines above 1"},
		{HostAdvanced{Routines: 2, PinThreadsKey: "tid"}, "advanced.pin_threads_key must be pid or port"},
		{HostAdvanced{Routines: 2, CPUAffinity: []int{-1}}, "advanced.cpu_affinity[0] must be between 0 and 4095"},
		{HostAdvanced{Routines: 2, CPUAffinity: make([]int, MaxCPUAffinityEntries+1)}, "at most 256 entries"},
		{HostAdvanced{LocalAPIControlGroup: "nebula\nadmins"}, "advanced.local_api_control_group must be a group name"},
		{HostAdvanced{LocalAPIControlGroup: strings.Repeat("g", MaxLocalAPIGroupLen+1)}, "advanced.local_api_control_group must be a group name"},
	}
	for i, tt := range invalid {
		err := ValidateHostAdvanced(&tt.adv)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("invalid[%d]: err = %v, want %q", i, err, tt.want)
		}
	}
}

func TestHostDiff_Tuning(t *testing.T) {
	yes := true
	before := &Host{Advanced: &HostAdvanced{}}
	after := &Host{Advanced: &HostAdvanced{
		Routines: 2, UDPOffloads: &yes, TunOffloads: &yes, PinThreads: &yes,
		PinThreadsKey: "port", CPUAffinity: []int{1}, LocalAPIControlEnabled: &yes, LocalAPIControlGroup: "nebula",
	}}
	diff, changed, err := HostDiff(before, after)
	if err != nil || !changed {
		t.Fatalf("HostDiff = %s, %v, %v", diff, changed, err)
	}
	var result map[string]map[string]any
	if err := json.Unmarshal(diff, &result); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"advanced.routines", "advanced.udp_offloads", "advanced.tun_offloads", "advanced.pin_threads",
		"advanced.pin_threads_key", "advanced.cpu_affinity", "advanced.local_api_control_enabled",
		"advanced.local_api_control_group",
	} {
		if _, ok := result[key]; !ok {
			t.Errorf("diff missing %s: %s", key, diff)
		}
	}
	if _, changed, _ := HostDiff(after, after); changed {
		t.Error("identical tuning reported as changed")
	}
}
