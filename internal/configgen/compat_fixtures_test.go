package configgen

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
)

// updateCompatFixtures rewrites testdata/nebulacompat. The fixtures are the
// configs tests/nebulacompat loads with the oldest supported Nebula release,
// which this module cannot import alongside the release it builds against.
var updateCompatFixtures = flag.Bool("update-compat", false, "rewrite testdata/nebulacompat fixtures")

// Placeholder PKI paths; tests/nebulacompat points them at a CA and host
// certificate it signs with the old release.
const (
	compatCAPath   = "/nebulacompat/ca.crt"
	compatCertPath = "/nebulacompat/host.crt"
	compatKeyPath  = "/nebulacompat/host.key"
)

func compatBaseInput() GeneratorInput {
	yes := true
	return GeneratorInput{
		HostName:    "web-1",
		NebulaIPs:   []string{"192.168.100.10"},
		CACertPath:  compatCAPath,
		CertPath:    compatCertPath,
		KeyPath:     compatKeyPath,
		ListenPort:  4242,
		Lighthouses: []LighthouseInfo{{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: "203.0.113.10:4242"}},
		Relays:      []string{"192.168.100.2"},
		FirewallInbound: []FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
			{Port: "22", Proto: "tcp", Group: "admin"},
		},
		FirewallOutbound:      []FirewallRule{{Port: "any", Proto: "any", Group: "any"}},
		PunchyRespondOverride: &yes,
		Blocklist:             []string{"c99d4e650533b92061b09918e838a5a0a6aaee21eed1d12fd937682865936c72"},
	}
}

// compatFixtures are the rendered shapes an old release must still load:
// the conservative config of a host with no known version, a lighthouse and
// relay, every pre-1.12 advanced override, and a host rendered for 1.12
// whose 1.12-only keys an older release must ignore.
func compatFixtures() map[string]GeneratorInput {
	conservative := compatBaseInput()

	lighthouse := compatBaseInput()
	lighthouse.IsLighthouse = true
	lighthouse.IsRelay = true

	overrides := compatBaseInput()
	no := false
	overrides.PunchyOverride = &no
	overrides.ListenHost = "[::]"
	overrides.MTU = 1400
	overrides.TunDevice = "nebula9"
	overrides.Routines = 2
	overrides.UnsafeRoutes = []AdvancedUnsafeRoute{{Route: "10.20.0.0/16", Via: "192.168.100.5"}}
	overrides.HostFirewallInbound = []FirewallRule{
		{Port: "443", Proto: "tcp", Cidr: "192.168.100.0/24"},
		{Port: "any", Proto: "any", Group: "gw", LocalCidr: "10.20.0.0/16"},
	}

	newer := compatBaseInput()
	yes := true
	newer.Runtime = nebulacompat.HostRuntime("1.12.0", "linux", "", false)
	newer.Routines = 4
	newer.UDPOffloads, newer.TunOffloads, newer.PinThreads = &yes, &yes, &yes
	newer.PinThreadsKey = "port"
	newer.CPUAffinity = []int{0, 1}
	newer.LocalAPIControlEnabled, newer.LocalAPIControlGroup = &no, "nebula"

	return map[string]GeneratorInput{
		"conservative.yml":       conservative,
		"lighthouse-relay.yml":   lighthouse,
		"advanced-overrides.yml": overrides,
		"rendered-for-1.12.yml":  newer,
	}
}

// TestCompatFixturesUpToDate keeps the fixtures in step with the generator;
// run `go test ./internal/configgen -run CompatFixtures -update-compat` after
// a renderer change.
func TestCompatFixturesUpToDate(t *testing.T) {
	dir := filepath.Join("testdata", "nebulacompat")
	for name, in := range compatFixtures() {
		out, err := Generate(in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		path := filepath.Join(dir, name)
		if *updateCompatFixtures {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, out, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path) // #nosec G304 -- fixture path built from a constant directory and a fixed name
		if err != nil {
			t.Fatalf("%s: %v (run with -update-compat)", name, err)
		}
		if string(want) != string(out) {
			t.Errorf("%s is stale; run go test ./internal/configgen -run CompatFixtures -update-compat", path)
		}
	}
}
