package configgen

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerate_RegularHost(t *testing.T) {
	input := GeneratorInput{
		HostName:    "web-1",
		NebulaIP:    "192.168.100.10",
		IsLighthouse: false,
		IsRelay:     false,
		CACertPath:  "/etc/nebula/ca.crt",
		CertPath:    "/etc/nebula/host.crt",
		KeyPath:     "/etc/nebula/host.key",
		ListenPort:  0,
		Lighthouses: []LighthouseInfo{
			{NebulaIP: "192.168.100.1", PublicAddr: "203.0.113.10:4242"},
		},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
			{Port: "22", Proto: "tcp", Group: "admin"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Validate it's valid YAML
	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	s := string(data)
	if !strings.Contains(s, "/etc/nebula/ca.crt") {
		t.Error("missing ca cert path")
	}
	if !strings.Contains(s, "203.0.113.10:4242") {
		t.Error("missing lighthouse public address")
	}
	if !strings.Contains(s, "192.168.100.1") {
		t.Error("missing lighthouse nebula IP")
	}
	// Regular host should not be a lighthouse
	if strings.Contains(s, "am_lighthouse: true") {
		t.Error("regular host should not be am_lighthouse")
	}
}

func TestGenerate_Lighthouse(t *testing.T) {
	input := GeneratorInput{
		HostName:     "lighthouse-1",
		NebulaIP:     "192.168.100.1",
		IsLighthouse: true,
		CACertPath:   "/etc/nebula/ca.crt",
		CertPath:     "/etc/nebula/host.crt",
		KeyPath:      "/etc/nebula/host.key",
		ListenPort:   4242,
		Lighthouses:  nil,
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	s := string(data)
	if !strings.Contains(s, "am_lighthouse: true") {
		t.Error("lighthouse should have am_lighthouse: true")
	}
	if !strings.Contains(s, "4242") {
		t.Error("lighthouse should have listen port")
	}
}

func TestGenerate_Relay(t *testing.T) {
	input := GeneratorInput{
		HostName:    "relay-1",
		NebulaIP:    "192.168.100.2",
		IsRelay:     true,
		CACertPath:  "/etc/nebula/ca.crt",
		CertPath:    "/etc/nebula/host.crt",
		KeyPath:     "/etc/nebula/host.key",
		ListenPort:  4242,
		Lighthouses: []LighthouseInfo{
			{NebulaIP: "192.168.100.1", PublicAddr: "203.0.113.10:4242"},
		},
		Relays: []string{"192.168.100.2"},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
		FirewallOutbound: []FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	}

	data, err := Generate(input)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	var parsed map[string]any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, string(data))
	}

	s := string(data)
	if !strings.Contains(s, "am_relay: true") {
		t.Error("relay should have am_relay: true")
	}
}
