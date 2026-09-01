package models

import (
	"strings"
	"testing"
)

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

// The profile describes the *agent's* filesystem, so validation must not depend
// on the server's GOOS. A Windows agent enrolling against a Linux management
// server was rejected with HTTP 400 "invalid agent profile"; the mirror case is
// why TestAgentProfileDefaultsAndValidation failed when run on Windows.
func TestAgentProfileValidate_AcceptsBothPathFlavours(t *testing.T) {
	valid := []AgentProfile{
		{
			NebulaConfigPath: `C:\ProgramData\Nebula\config.yml`,
			NebulaCAPath:     `C:\ProgramData\Nebula\ca.crt`,
			NebulaCertPath:   `C:\ProgramData\Nebula\host.crt`,
			NebulaKeyPath:    `C:\ProgramData\Nebula\host.key`,
			ConfigAckV1:      true,
		},
		{
			NebulaConfigPath: `\\fileserver\nebula\config.yml`,
			NebulaCAPath:     `\\fileserver\nebula\ca.crt`,
			NebulaCertPath:   `\\fileserver\nebula\host.crt`,
			NebulaKeyPath:    `\\fileserver\nebula\host.key`,
		},
		DefaultAgentProfile(),
	}
	for _, profile := range valid {
		if err := profile.Validate(); err != nil {
			t.Errorf("rejected valid profile %#v: %v", profile, err)
		}
	}
}

// Widening the check to Windows paths must not weaken any of the other rules.
func TestAgentProfileValidate_RejectsMalformedPaths(t *testing.T) {
	cases := map[string]string{
		"relative windows":     `ProgramData\Nebula\config.yml`,
		"drive relative":       `C:config.yml`,
		"parent traversal":     `C:\ProgramData\..\Windows\System32\config.yml`,
		"dot segment":          `C:\ProgramData\.\Nebula\config.yml`,
		"repeated separator":   "C:\\ProgramData\\\\Nebula\\config.yml",
		"trailing separator":   `C:\ProgramData\Nebula\`,
		"bare drive root":      `C:\`,
		"forward slash mix":    `C:/ProgramData/Nebula/config.yml`,
		"unc without share":    `\\fileserver`,
		"unc bare root":        `\\fileserver\nebula`,
		"unc empty server":     `\\\share\config.yml`,
		"posix bare root":      `/`,
		"posix traversal":      `/etc/nebula/../bad`,
		"posix trailing slash": `/etc/nebula/`,
		"posix relative":       `etc/nebula/config.yml`,
		"nul byte":             "C:\\ProgramData\\Nebula\\con\x00fig.yml",
	}
	for name, bad := range cases {
		profile := AgentProfile{
			NebulaConfigPath: bad,
			NebulaCAPath:     `C:\ProgramData\Nebula\ca.crt`,
			NebulaCertPath:   `C:\ProgramData\Nebula\host.crt`,
			NebulaKeyPath:    `C:\ProgramData\Nebula\host.key`,
		}
		if err := profile.Validate(); err == nil {
			t.Errorf("%s: accepted %q", name, bad)
		}
	}
}

// The four paths must still be distinct, in either flavour.
func TestAgentProfileValidate_RejectsDuplicateWindowsPaths(t *testing.T) {
	profile := AgentProfile{
		NebulaConfigPath: `C:\ProgramData\Nebula\same.yml`,
		NebulaCAPath:     `C:\ProgramData\Nebula\same.yml`,
		NebulaCertPath:   `C:\ProgramData\Nebula\host.crt`,
		NebulaKeyPath:    `C:\ProgramData\Nebula\host.key`,
	}
	if err := profile.Validate(); err == nil {
		t.Fatal("accepted duplicate paths")
	}
}

// An over-long path stays rejected regardless of flavour.
func TestAgentProfileValidate_RejectsOverlongPath(t *testing.T) {
	long := `C:\` + strings.Repeat("a", maxAgentProfilePathBytes)
	profile := AgentProfile{
		NebulaConfigPath: long,
		NebulaCAPath:     `C:\ProgramData\Nebula\ca.crt`,
		NebulaCertPath:   `C:\ProgramData\Nebula\host.crt`,
		NebulaKeyPath:    `C:\ProgramData\Nebula\host.key`,
	}
	if err := profile.Validate(); err == nil {
		t.Fatal("accepted an over-long path")
	}
}
