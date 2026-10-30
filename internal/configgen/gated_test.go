package configgen

import (
	"reflect"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
)

func tuningInput(rt nebulacompat.Runtime) GeneratorInput {
	in := baseRoundTripInput()
	yes, no := true, false
	in.Runtime = rt
	in.Routines = 4
	in.UDPOffloads = &yes
	in.TunOffloads = &yes
	in.PinThreads = &no
	in.PinThreadsKey = "port"
	in.CPUAffinity = []int{0, 2}
	in.LocalAPIControlEnabled = &no
	in.LocalAPIControlGroup = "007"
	return in
}

func TestGenerate_GatedFeaturesFollowHostRuntime(t *testing.T) {
	tests := []struct {
		name                        string
		rt                          nebulacompat.Runtime
		offloads, pinning, localAPI bool
	}{
		{"unknown version", nebulacompat.Runtime{}, false, false, false},
		{"1.11 on linux", nebulacompat.HostRuntime("1.11.2", "linux", "", false), false, false, false},
		{"1.12 on linux", nebulacompat.HostRuntime("1.12.0", "linux", "", false), true, true, true},
		{"1.12 on unknown OS", nebulacompat.HostRuntime("", "", "1.12.0", false), true, true, true},
		{"1.12 on windows", nebulacompat.HostRuntime("1.12.0", "windows", "", false), false, false, true},
		{"mobile on 1.12", nebulacompat.HostRuntime("", "", "1.12.0", true), false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := loadGenerated(t, tuningInput(tt.rt))

			// routines is understood by every supported release.
			if got := c.GetInt("routines", 0); got != 4 {
				t.Errorf("routines = %d, want 4", got)
			}
			// The keys pinning pre-1.11 Windows behavior stay for every host.
			if c.GetBool("listen.windows_bypass_wdf", true) || c.GetString("tun.network_category", "") != "unset" {
				t.Error("Windows compatibility defaults missing")
			}

			if got := c.IsSet("listen.udp_offloads") && c.IsSet("tun.use_offloads"); got != tt.offloads {
				t.Errorf("offloads rendered = %v, want %v", got, tt.offloads)
			}
			if tt.offloads && (!c.GetBool("listen.udp_offloads", false) || !c.GetBool("tun.use_offloads", false)) {
				t.Error("offloads rendered with wrong values")
			}

			if got := c.IsSet("tun.pin_threads"); got != tt.pinning {
				t.Errorf("pin_threads rendered = %v, want %v", got, tt.pinning)
			}
			if tt.pinning {
				if c.GetBool("tun.pin_threads", true) || c.GetString("tun.pin_threads_key", "") != "port" {
					t.Error("pinning rendered with wrong values")
				}
				if got := c.Get("tun.cpu_affinity"); !reflect.DeepEqual(got, []any{0, 2}) {
					t.Errorf("tun.cpu_affinity = %#v, want [0 2]", got)
				}
			}

			if got := c.IsSet("local_api.control.enabled"); got != tt.localAPI {
				t.Errorf("local_api rendered = %v, want %v", got, tt.localAPI)
			}
			// A numeric-looking group must reach Nebula as the string "007".
			if tt.localAPI && (c.GetBool("local_api.control.enabled", true) || c.GetString("local_api.control.group", "") != "007") {
				t.Errorf("local_api rendered with wrong values: group=%q", c.GetString("local_api.control.group", ""))
			}
		})
	}
}

func TestGenerate_NoTuningRendersNoNewKeys(t *testing.T) {
	in := baseRoundTripInput()
	in.Runtime = nebulacompat.HostRuntime("1.12.0", "linux", "", false)
	c := loadGenerated(t, in)
	for _, key := range []string{"routines", "listen.udp_offloads", "tun.use_offloads", "tun.pin_threads", "tun.cpu_affinity", "local_api"} {
		if c.IsSet(key) {
			t.Errorf("%s rendered without an override", key)
		}
	}
}
