package configgen

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestGenerate_BlocklistEmitted verifies that a non-empty blocklist is
// rendered as pki.blocklist in the generated config (GHSA-cm26-5974-52h8).
func TestGenerate_BlocklistEmitted(t *testing.T) {
	input := GeneratorInput{
		HostName:   "web-1",
		NebulaIPs:  []string{"192.168.100.10"},
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		Blocklist: []string{"fp-revoked-1", "fp-revoked-2"},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	pki, ok := parsed["pki"].(map[string]any)
	if !ok {
		t.Fatal("missing pki section")
	}
	bl, ok := pki["blocklist"].([]any)
	if !ok {
		t.Fatalf("pki.blocklist missing or wrong type; got %T\n%s", pki["blocklist"], string(data))
	}
	if len(bl) != 2 {
		t.Fatalf("pki.blocklist len = %d, want 2", len(bl))
	}

	s := string(data)
	if !strings.Contains(s, "fp-revoked-1") || !strings.Contains(s, "fp-revoked-2") {
		t.Errorf("blocklist fingerprints missing from output:\n%s", s)
	}
}

// TestGenerate_BlocklistOmittedWhenEmpty verifies that an empty blocklist
// does not produce a pki.blocklist key — so existing configs stay clean.
func TestGenerate_BlocklistOmittedWhenEmpty(t *testing.T) {
	input := GeneratorInput{
		HostName:   "web-1",
		NebulaIPs:  []string{"192.168.100.10"},
		CACertPath: "/etc/nebula/ca.crt",
		CertPath:   "/etc/nebula/host.crt",
		KeyPath:    "/etc/nebula/host.key",
		Lighthouses: []LighthouseInfo{
			{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	s := string(data)
	if strings.Contains(s, "blocklist") {
		t.Errorf("empty blocklist should be omitted, but output contains 'blocklist':\n%s", s)
	}
}
