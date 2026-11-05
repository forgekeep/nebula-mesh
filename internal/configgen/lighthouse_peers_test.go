package configgen

import (
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGenerate_LighthousesCanReachEachOther(t *testing.T) {
	lighthouses := []LighthouseInfo{
		{NebulaIPs: []string{"192.168.100.1", "fd00::1"}, PublicAddr: "203.0.113.10:4242"},
		{NebulaIPs: []string{"192.168.100.2", "fd00::2"}, PublicAddr: "203.0.113.20:4242"},
	}
	for _, own := range lighthouses {
		t.Run(own.NebulaIPs[0], func(t *testing.T) {
			data, err := Generate(GeneratorInput{
				NebulaIPs: own.NebulaIPs, IsLighthouse: true, Lighthouses: lighthouses,
			})
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				StaticHostMap map[string][]string `yaml:"static_host_map"`
				Lighthouse    struct {
					AmLighthouse bool     `yaml:"am_lighthouse"`
					Hosts        []string `yaml:"hosts"`
				} `yaml:"lighthouse"`
			}
			if err := yaml.Unmarshal(data, &parsed); err != nil {
				t.Fatal(err)
			}
			if !parsed.Lighthouse.AmLighthouse || len(parsed.Lighthouse.Hosts) != 0 {
				t.Fatalf("lighthouses must remain independent: %+v", parsed.Lighthouse)
			}
			for _, peer := range lighthouses {
				for _, ip := range peer.NebulaIPs {
					if peer.PublicAddr == own.PublicAddr {
						if _, ok := parsed.StaticHostMap[ip]; ok {
							t.Errorf("lighthouse advertises itself as a remote: %s", ip)
						}
						continue
					}
					if got := parsed.StaticHostMap[ip]; len(got) != 1 || got[0] != peer.PublicAddr {
						t.Errorf("cannot locate peer %s: got %v, want [%s]", ip, got, peer.PublicAddr)
					}
				}
			}
		})
	}
}

// TestGenerate_LighthouseExtraAddrs: a lighthouse's extra endpoints follow its
// public one in the same static_host_map entry, for plain hosts and for peer
// lighthouses alike, so Nebula tries every address of that lighthouse.
func TestGenerate_LighthouseExtraAddrs(t *testing.T) {
	lighthouses := []LighthouseInfo{
		{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242",
			ExtraAddrs: []string{"192.168.1.10:4242", "[2001:db8::10]:4242"}},
		{NebulaIPs: []string{"192.168.100.2"}, PublicAddr: "203.0.113.20:4242"},
	}
	want := []string{"203.0.113.10:4242", "192.168.1.10:4242", "[2001:db8::10]:4242"}
	for name, input := range map[string]GeneratorInput{
		"host":            {NebulaIPs: []string{"192.168.100.10"}, Lighthouses: lighthouses},
		"peer lighthouse": {NebulaIPs: []string{"192.168.100.2"}, IsLighthouse: true, Lighthouses: lighthouses},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := Generate(input)
			if err != nil {
				t.Fatal(err)
			}
			var parsed parsedConfig
			if err := yaml.Unmarshal(data, &parsed); err != nil {
				t.Fatal(err)
			}
			if got := parsed.StaticHostMap["192.168.100.1"]; !slices.Equal(got, want) {
				t.Fatalf("static_host_map[192.168.100.1] = %v, want %v", got, want)
			}
		})
	}
}
