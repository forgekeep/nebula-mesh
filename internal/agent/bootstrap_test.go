package agent

import "testing"

func TestDecideBootstrapStatePurposeMatrix(t *testing.T) {
	tests := []struct {
		name  string
		state DiscoveryState
		token string
		force bool
		want  BootstrapAction
		err   bool
	}{
		{"fresh enrollment", DiscoveryNone, "nme_value", false, BootstrapEnroll, false},
		{"legacy fresh enrollment", DiscoveryNone, "legacy-token", false, BootstrapEnroll, false},
		{"fresh import refused", DiscoveryNone, "nmi_value", false, "", true},
		{"existing import", DiscoveryComplete, "nmi_value", false, BootstrapImport, false},
		{"existing enrollment refused", DiscoveryComplete, "nme_value", false, "", true},
		{"existing forced enrollment", DiscoveryComplete, "nme_value", true, BootstrapEnroll, false},
		{"existing forced legacy enrollment", DiscoveryComplete, "legacy-token", true, BootstrapEnroll, false},
		{"unsafe import refused", DiscoveryUnsafe, "nmi_value", true, "", true},
		{"unsafe forced enrollment", DiscoveryUnsafe, "nme_value", true, BootstrapEnroll, false},
		{"unknown prefix refused", DiscoveryNone, "nmz_value", false, "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := DecideBootstrap(test.state, test.token, test.force)
			if (err != nil) != test.err || got != test.want {
				t.Fatalf("DecideBootstrap = %q, %v; want %q, err=%t", got, err, test.want, test.err)
			}
		})
	}
}
