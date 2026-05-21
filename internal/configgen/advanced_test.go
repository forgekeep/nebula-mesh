package configgen

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

// TestGenerate_TunDevice_StructuralBreakCharsAreQuoted is the GHSA-7hp6
// defense-in-depth assertion (issue #126): even if the upstream TunDevice
// validator were bypassed, yaml.v3 marshaling MUST emit structural-break
// characters as safely-quoted scalars so they cannot escape into YAML
// structure. Each pathological TunDevice value below round-trips through
// yaml.Unmarshal exactly — no new top-level keys, no value corruption.
func TestGenerate_TunDevice_StructuralBreakCharsAreQuoted(t *testing.T) {
	cases := []string{
		"nebula0\rinjected: true", // CR — splits lines in plain scalars
		"nebula0\ninjected: true", // LF — same
		"nebula0\x05ctrl",         // ENQ — arbitrary control character
		`nebula0"quote`,           // double-quote — terminates quoted scalars
		"nebula0:colon",           // colon — key separator in plain scalars
		"nebula0#hash",            // hash — comment indicator
		"nebula0 trailing-space ", // leading/trailing whitespace stripping
	}

	for _, dev := range cases {
		t.Run(dev, func(t *testing.T) {
			out, err := Generate(GeneratorInput{
				HostName:   "h",
				NebulaIPs:  []string{"10.0.0.1"},
				CACertPath: "/etc/nebula/ca.crt",
				CertPath:   "/etc/nebula/host.crt",
				KeyPath:    "/etc/nebula/host.key",
				TunDevice:  dev,
			})
			if err != nil {
				t.Fatalf("Generate(%q): %v", dev, err)
			}

			var parsed struct {
				Tun struct {
					Dev string `yaml:"dev"`
				} `yaml:"tun"`
			}
			if err := yaml.Unmarshal(out, &parsed); err != nil {
				t.Fatalf("invalid YAML for %q: %v\n%s", dev, err, string(out))
			}
			if parsed.Tun.Dev != dev {
				t.Errorf("round-trip mismatch for %q:\n  got: %q\n output:\n%s", dev, parsed.Tun.Dev, string(out))
			}

			// Also assert no injection happened at the top level — only
			// the expected keys exist after unmarshal.
			var top map[string]any
			if err := yaml.Unmarshal(out, &top); err != nil {
				t.Fatalf("invalid YAML (top-level) for %q: %v", dev, err)
			}
			allowed := map[string]bool{
				"pki": true, "static_host_map": true, "lighthouse": true,
				"listen": true, "punchy": true, "tun": true, "relay": true,
				"logging": true, "firewall": true,
			}
			for k := range top {
				if !allowed[k] {
					t.Errorf("unexpected top-level key %q for TunDevice=%q — possible YAML injection", k, dev)
				}
			}
		})
	}
}
