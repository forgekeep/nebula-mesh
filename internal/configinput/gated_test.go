package configinput

import (
	"strings"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func host(version, os, operator string, adv models.HostAdvanced) *models.Host {
	adv.NebulaVersion = operator
	return &models.Host{NebulaVersion: version, NebulaOS: os, Advanced: &adv}
}

func TestCheckGatedOverrides(t *testing.T) {
	yes := true
	offloads := models.HostAdvanced{UDPOffloads: &yes}
	tests := []struct {
		name    string
		before  *models.Host
		after   *models.Host
		wantErr string
	}{
		{"new host, unknown version", nil, host("", "", "", offloads), ""},
		{"new host, operator 1.12", nil, host("", "", "1.12.0", offloads), ""},
		{"new host, operator 1.11", nil, host("", "", "1.11.2", offloads),
			"advanced.udp_offloads: UDP and tun offloads requires Nebula 1.12.0 or newer; host runs 1.11.2"},
		{"windows host", host("1.12.0", "windows", "", models.HostAdvanced{}), host("1.12.0", "windows", "", offloads),
			"advanced.udp_offloads: UDP and tun offloads requires linux; host reports windows"},
		{"unchanged after downgrade", host("1.11.2", "linux", "", offloads), host("1.11.2", "linux", "", offloads), ""},
		{"changed after downgrade", host("1.11.2", "linux", "", models.HostAdvanced{}),
			host("1.11.2", "linux", "", models.HostAdvanced{LocalAPIControlGroup: "nebula"}),
			"advanced.local_api_control_group: local API control socket requires Nebula 1.12.0 or newer; host runs 1.11.2"},
		{"mobile", nil, &models.Host{Kind: models.HostKindMobile, Advanced: &models.HostAdvanced{NebulaVersion: "1.12.0", Routines: 2, PinThreads: &yes}},
			"advanced.pin_threads: thread pinning does not apply to mobile clients"},
		{"routines alone is never gated", nil, host("1.10.3", "linux", "", models.HostAdvanced{Routines: 4}), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckGatedOverrides(tt.before, tt.after)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestUnappliedOverrides(t *testing.T) {
	yes := true
	h := host("1.12.0", "windows", "", models.HostAdvanced{UDPOffloads: &yes, LocalAPIControlEnabled: &yes})
	got := UnappliedOverrides(h)
	if len(got) != 1 || got[0].Fields[0] != "advanced.udp_offloads" || !strings.Contains(got[0].Status.Reason, "requires linux") {
		t.Fatalf("UnappliedOverrides = %+v, want only the offloads on windows", got)
	}
	unknown := host("", "", "", models.HostAdvanced{UDPOffloads: &yes, LocalAPIControlEnabled: &yes})
	if got := UnappliedOverrides(unknown); len(got) != 2 {
		t.Fatalf("unknown version: %d unapplied groups, want 2", len(got))
	}
	if got := UnappliedOverrides(host("1.12.0", "linux", "", models.HostAdvanced{UDPOffloads: &yes})); len(got) != 0 {
		t.Fatalf("supported host: unapplied = %+v", got)
	}
}
