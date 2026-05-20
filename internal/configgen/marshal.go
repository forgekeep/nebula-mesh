package configgen

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// nebulaConfig is the internal typed-struct representation of a Nebula agent
// config.yml. It exists so Generate can marshal through gopkg.in/yaml.v3
// instead of string-interpolating into a text/template. Every value is
// quoted/escaped by yaml.v3 according to YAML spec, so structural-break
// characters (CR/LF, control chars, ", :, #) in fields like TunDevice can
// never escape into the YAML structure regardless of what upstream validators
// allow. Defense-in-depth on top of input validation (GHSA-7hp6, issue #126).
type nebulaConfig struct {
	PKI           pkiSection          `yaml:"pki"`
	StaticHostMap map[string][]string `yaml:"static_host_map"`
	Lighthouse    lighthouseSection   `yaml:"lighthouse"`
	Listen        listenSection       `yaml:"listen"`
	Punchy        punchySection       `yaml:"punchy"`
	Tun           *tunSection         `yaml:"tun,omitempty"`
	Relay         *relaySection       `yaml:"relay,omitempty"`
	Logging       loggingSection      `yaml:"logging"`
	Firewall      firewallSection     `yaml:"firewall"`
}

// pkiSection's fields are typed `any` because inline PEMs marshal as
// literal-block scalars (via literalString.MarshalYAML) while path-based
// values are plain strings.
type pkiSection struct {
	CA   any `yaml:"ca"`
	Cert any `yaml:"cert"`
	Key  any `yaml:"key"`
}

// literalString marshals as a YAML literal-block scalar (|). Used for the
// inline PEM blocks so the multi-line content is preserved verbatim.
type literalString string

func (l literalString) MarshalYAML() (any, error) {
	return &yaml.Node{
		Kind:  yaml.ScalarNode,
		Style: yaml.LiteralStyle,
		Value: string(l),
	}, nil
}

type lighthouseSection struct {
	AmLighthouse bool     `yaml:"am_lighthouse"`
	Hosts        []string `yaml:"hosts,omitempty"`
}

type listenSection struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type punchySection struct {
	Punch bool `yaml:"punch"`
}

type tunSection struct {
	Dev          string        `yaml:"dev,omitempty"`
	MTU          int           `yaml:"mtu,omitempty"`
	UnsafeRoutes []unsafeRoute `yaml:"unsafe_routes,omitempty"`
}

type unsafeRoute struct {
	Route string `yaml:"route"`
	Via   string `yaml:"via"`
}

type relaySection struct {
	AmRelay bool     `yaml:"am_relay,omitempty"`
	Relays  []string `yaml:"relays,omitempty"`
}

type loggingSection struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type firewallSection struct {
	Outbound []firewallRule `yaml:"outbound"`
	Inbound  []firewallRule `yaml:"inbound"`
}

// firewallRule is constructed with exactly one of {Group, Host} set per rule —
// matching the shape the previous template emitted: `group: <name>` for named
// groups, `host: any` for the catch-all.
type firewallRule struct {
	Port  string `yaml:"port"`
	Proto string `yaml:"proto"`
	Group string `yaml:"group,omitempty"`
	Host  string `yaml:"host,omitempty"`
}

// Generate produces a Nebula config.yml from the given input by marshaling
// a typed struct through gopkg.in/yaml.v3. Replaces the previous
// text/template-based generator (GHSA-7hp6 follow-up, issue #126).
func Generate(input GeneratorInput) ([]byte, error) {
	cfg := buildConfig(input)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close encoder: %w", err)
	}
	return buf.Bytes(), nil
}

func buildConfig(input GeneratorInput) nebulaConfig {
	cfg := nebulaConfig{
		Logging: loggingSection{Level: "info", Format: "text"},
	}

	if input.CACertPEM != "" {
		cfg.PKI = pkiSection{
			CA:   literalString(input.CACertPEM),
			Cert: literalString(input.CertPEM),
			Key:  literalString(input.KeyPEM),
		}
	} else {
		cfg.PKI = pkiSection{
			CA:   input.CACertPath,
			Cert: input.CertPath,
			Key:  input.KeyPath,
		}
	}

	cfg.StaticHostMap = map[string][]string{}
	if input.IsLighthouse {
		cfg.Lighthouse = lighthouseSection{AmLighthouse: true}
	} else {
		var hosts []string
		for _, lh := range input.Lighthouses {
			for _, ip := range lh.NebulaIPs {
				cfg.StaticHostMap[ip] = []string{lh.PublicAddr}
				hosts = append(hosts, ip)
			}
		}
		cfg.Lighthouse = lighthouseSection{AmLighthouse: false, Hosts: hosts}
	}

	listenHost := input.ListenHost
	if listenHost == "" {
		listenHost = "0.0.0.0"
	}
	listenPort := input.ListenPort
	if listenPort == 0 && input.IsLighthouse {
		listenPort = 4242
	}
	cfg.Listen = listenSection{Host: listenHost, Port: listenPort}

	punch := true
	if input.PunchyOverride != nil {
		punch = *input.PunchyOverride
	}
	cfg.Punchy = punchySection{Punch: punch}

	if input.MTU != 0 || input.TunDevice != "" || len(input.UnsafeRoutes) > 0 {
		ts := &tunSection{Dev: input.TunDevice, MTU: input.MTU}
		for _, r := range input.UnsafeRoutes {
			ts.UnsafeRoutes = append(ts.UnsafeRoutes, unsafeRoute(r))
		}
		cfg.Tun = ts
	}

	if input.IsRelay {
		cfg.Relay = &relaySection{AmRelay: true}
	} else if len(input.Relays) > 0 {
		cfg.Relay = &relaySection{Relays: input.Relays}
	}

	cfg.Firewall.Outbound = mapFirewallRules(input.FirewallOutbound)
	cfg.Firewall.Inbound = mapFirewallRules(input.FirewallInbound)

	return cfg
}

func mapFirewallRules(in []FirewallRule) []firewallRule {
	out := make([]firewallRule, 0, len(in))
	for _, r := range in {
		fr := firewallRule{Port: r.Port, Proto: r.Proto}
		if r.Group == "any" {
			fr.Host = "any"
		} else {
			fr.Group = r.Group
		}
		out = append(out, fr)
	}
	return out
}
