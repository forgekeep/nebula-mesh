package models

import "testing"

func TestAgentProfileDefaultsAndValidation(t *testing.T) {
	profile := DefaultAgentProfile()
	if profile.NebulaConfigPath != "/etc/nebula/config.yml" || profile.NebulaCAPath != "/etc/nebula/ca.crt" ||
		profile.NebulaCertPath != "/etc/nebula/host.crt" || profile.NebulaKeyPath != "/etc/nebula/host.key" {
		t.Fatalf("defaults = %#v", profile)
	}
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []AgentProfile{
		{NebulaConfigPath: "relative.yml", NebulaCAPath: "/ca", NebulaCertPath: "/cert", NebulaKeyPath: "/key"},
		{NebulaConfigPath: "/etc/nebula/../bad", NebulaCAPath: "/ca", NebulaCertPath: "/cert", NebulaKeyPath: "/key"},
		{NebulaConfigPath: "/same", NebulaCAPath: "/same", NebulaCertPath: "/cert", NebulaKeyPath: "/key"},
	} {
		if err := invalid.Validate(); err == nil {
			t.Fatalf("invalid profile accepted: %#v", invalid)
		}
	}
}
