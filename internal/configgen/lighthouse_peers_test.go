package configgen

import (
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
