package nebulacompat

import "testing"

func TestRuntimeCheck(t *testing.T) {
	tests := []struct {
		name     string
		rt       Runtime
		feature  Feature
		rendered bool
		definite bool
		reason   string
	}{
		{"linux 1.12 offloads", HostRuntime("1.12.0", "linux", "", false), FeatureOffloads, true, false, ""},
		{"unknown OS 1.12 offloads", HostRuntime("1.12.0", "", "", false), FeatureOffloads, true, false, ""},
		{"operator 1.12 local api", HostRuntime("", "", "1.12.0", false), FeatureLocalAPI, true, false, ""},
		{"newer release", HostRuntime("2.0.0", "linux", "", false), FeatureOffloads, true, false, ""},
		{"windows offloads", HostRuntime("1.12.0", "windows", "", false), FeatureOffloads, false, true,
			"UDP and tun offloads requires linux; host reports windows"},
		{"linux 1.11 offloads", HostRuntime("1.11.2", "linux", "", false), FeatureOffloads, false, true,
			"UDP and tun offloads requires Nebula 1.12.0 or newer; host runs 1.11.2"},
		{"release candidate", HostRuntime("1.12.0-rc1", "linux", "", false), FeatureOffloads, false, true,
			"UDP and tun offloads requires Nebula 1.12.0 or newer; host runs 1.12.0-rc1"},
		{"unknown version", Runtime{}, FeatureLocalAPI, false, false,
			"local API control socket requires Nebula 1.12.0 or newer; the host's Nebula version is unknown"},
		{"below minimum", HostRuntime("1.9.4", "linux", "", false), FeatureLocalAPI, false, true,
			"host runs Nebula 1.9.4, below the oldest supported release 1.10.0"},
		{"mobile", HostRuntime("", "", "1.12.0", true), FeatureLocalAPI, false, true,
			"local API control socket does not apply to mobile clients"},
		{"darwin dns", HostRuntime("1.12.0", "darwin", "", false), FeatureHostDNS, true, false, ""},
		{"linux dns", HostRuntime("1.12.0", "linux", "", false), FeatureHostDNS, false, true,
			"host DNS requires darwin or windows; host reports linux"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rt.Check(tt.feature)
			if got.Rendered != tt.rendered || got.Definite != tt.definite || got.Reason != tt.reason {
				t.Errorf("Check = %+v, want rendered=%v definite=%v reason=%q", got, tt.rendered, tt.definite, tt.reason)
			}
		})
	}
}

func TestHostRuntime_AgentReportWins(t *testing.T) {
	rt := HostRuntime("1.11.2", "linux", "1.12.0", false)
	if rt.Version.String() != "1.11.2" || rt.Source != SourceAgent {
		t.Errorf("runtime = %+v", rt)
	}
}
