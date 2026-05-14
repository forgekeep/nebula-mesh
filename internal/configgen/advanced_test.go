package configgen

import (
	"strings"
	"testing"
)

func TestGenerate_DefaultsWhenNoAdvanced(t *testing.T) {
	out, err := Generate(GeneratorInput{
		HostName:   "h",
		NebulaIPs:  []string{"10.0.0.1"},
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "host: 0.0.0.0") {
		t.Error("expected default listen.host 0.0.0.0")
	}
	if !strings.Contains(s, "punch: true") {
		t.Error("expected default punch: true")
	}
	if strings.Contains(s, "tun:") {
		t.Error("tun block should not appear without advanced overrides")
	}
	if strings.Contains(s, "unsafe_routes") {
		t.Error("unsafe_routes should not appear without advanced overrides")
	}
}

func TestGenerate_AdvancedListenHostAndMTU(t *testing.T) {
	out, err := Generate(GeneratorInput{
		HostName:   "h",
		NebulaIPs:  []string{"10.0.0.1"},
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
		ListenHost: "10.0.0.1",
		MTU:        1300,
		TunDevice:  "nebula1",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "host: 10.0.0.1") {
		t.Error("override listen.host missing")
	}
	if !strings.Contains(s, "mtu: 1300") {
		t.Error("tun.mtu missing")
	}
	if !strings.Contains(s, "dev: nebula1") {
		t.Error("tun.dev missing")
	}
}

func TestGenerate_AdvancedUnsafeRoutes(t *testing.T) {
	out, err := Generate(GeneratorInput{
		HostName:   "h",
		NebulaIPs:  []string{"10.0.0.1"},
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
		UnsafeRoutes: []AdvancedUnsafeRoute{
			{Route: "192.168.10.0/24", Via: "10.0.0.99"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "unsafe_routes:") {
		t.Error("unsafe_routes section missing")
	}
	if !strings.Contains(s, "route: 192.168.10.0/24") {
		t.Error("unsafe route entry missing")
	}
	if !strings.Contains(s, "via: 10.0.0.99") {
		t.Error("unsafe route via missing")
	}
}

func TestGenerate_PunchyOverride(t *testing.T) {
	f := false
	out, err := Generate(GeneratorInput{
		HostName:       "h",
		NebulaIPs:      []string{"10.0.0.1"},
		CACertPath:     "/etc/nebula/ca.crt",
		CertPath:       "/etc/nebula/host.crt",
		KeyPath:        "/etc/nebula/host.key",
		PunchyOverride: &f,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "punch: false") {
		t.Errorf("expected punch: false override; got:\n%s", out)
	}
}
