package configgen

import (
	"testing"

	nebcfg "github.com/slackhq/nebula/config"
	"gopkg.in/yaml.v3"
)

// FuzzGenerate asserts the invariant the typed-struct generator was built to
// guarantee (GHSA-7hp6, issue #126): no operator-controlled field can break
// out of the YAML structure, and the result is something a real Nebula agent
// can actually load. For every input:
//
//  1. Generate must succeed (it only marshals a typed struct, so the only
//     possible error is an encoder fault, which would be a regression).
//  2. The output must re-parse through Nebula's *own* config loader — the
//     same code path an agent runs on SIGHUP. "Valid YAML" is necessary but
//     not sufficient; this checks the parser the agent will actually use.
//  3. The scalar fields an agent reads (am_lighthouse, punchy.punch,
//     listen.port) must round-trip with their Go type intact. A quoted bool
//     or stringified int still parses as YAML but silently changes behavior
//     on reload, so the assertions go through the same accessors the agent
//     uses (GetBool / GetInt), not a raw map compare.
//
// config.C's LoadString/Get/GetString/GetBool/GetInt never touch its
// (here nil) logger, so a zero-value C is safe and this target adds no new
// module dependency.
//
// Run the seed corpus with the rest of the unit tests; explore with
//
//	go test ./internal/configgen/ -run '^$' -fuzz='^FuzzGenerate$'
func FuzzGenerate(f *testing.F) {
	// Seeds mirror the table-driven cases in generator_test.go: a regular
	// host, a lighthouse, and a mobile (inline-PEM) host.
	f.Add("web-1", "192.168.100.10", "192.168.100.1", "203.0.113.10:4242",
		"", "", "any", "icmp", "any", 0, 0, false, false, true, false, "")
	f.Add("lh-1", "10.0.0.1", "", "", "0.0.0.0", "nebula1", "22", "tcp", "admin",
		4242, 1300, true, false, false, false, "")
	f.Add("mobile", "10.0.0.5", "10.0.0.1", "198.51.100.7:4242",
		"", "", "443", "udp", "ops", 0, 0, false, true, true, true,
		"-----BEGIN NEBULA CERTIFICATE-----\nAQ==\n-----END NEBULA CERTIFICATE-----")

	f.Fuzz(func(t *testing.T,
		hostName, ip, lhIP, lhAddr, listenHost, tunDev, fwPort, fwProto, fwGroup string,
		listenPort, mtu int, isLH, isRelay, punch, inlinePEM bool, pemBlock string,
	) {
		punchy := punch // address-of a copy; PunchyOverride wants *bool
		in := GeneratorInput{
			HostName:         hostName,
			NebulaIPs:        []string{ip},
			IsLighthouse:     isLH,
			IsRelay:          isRelay,
			ListenPort:       listenPort,
			ListenHost:       listenHost,
			MTU:              mtu,
			TunDevice:        tunDev,
			PunchyOverride:   &punchy,
			Lighthouses:      []LighthouseInfo{{NebulaIPs: []string{lhIP}, PublicAddr: lhAddr}},
			FirewallInbound:  []FirewallRule{{Port: fwPort, Proto: fwProto, Group: fwGroup}},
			FirewallOutbound: []FirewallRule{{Port: fwPort, Proto: fwProto, Group: fwGroup}},
		}
		// Generate only emits the inline-PEM section when CACertPEM is set
		// (see buildConfig); otherwise it falls back to the path form.
		if inlinePEM && pemBlock != "" {
			in.CACertPEM, in.CertPEM, in.KeyPEM = pemBlock, pemBlock, pemBlock
		} else {
			in.CACertPath = "/etc/nebula/ca.crt"
			in.CertPath = "/etc/nebula/host.crt"
			in.KeyPath = "/etc/nebula/host.key"
		}

		out, err := Generate(in)
		if err != nil {
			t.Fatalf("Generate errored on structured input: %v", err)
		}

		// (1) Well-formed YAML — cheap, and gives the clearest failure first.
		var sink map[string]any
		if err := yaml.Unmarshal(out, &sink); err != nil {
			t.Fatalf("generator emitted invalid YAML: %v\n--- config ---\n%s", err, out)
		}

		// (2) Loads in Nebula's own parser (the real SIGHUP-reload path).
		var c nebcfg.C
		if err := c.LoadString(string(out)); err != nil {
			t.Fatalf("Nebula config.LoadString rejected generated config: %v\n--- config ---\n%s", err, out)
		}

		// (3) Type-preserving round-trip of the scalars the agent reads.
		if got := c.GetBool("lighthouse.am_lighthouse", !isLH); got != isLH {
			t.Fatalf("am_lighthouse round-trip: got %v want %v\n--- config ---\n%s", got, isLH, out)
		}
		if got := c.GetBool("punchy.punch", !punchy); got != punchy {
			t.Fatalf("punchy.punch round-trip: got %v want %v\n--- config ---\n%s", got, punchy, out)
		}
		wantPort := listenPort
		if wantPort == 0 && isLH {
			wantPort = 4242 // generator's lighthouse default
		}
		if got := c.GetInt("listen.port", wantPort-1); got != wantPort {
			t.Fatalf("listen.port round-trip: got %d want %d\n--- config ---\n%s", got, wantPort, out)
		}
	})
}
