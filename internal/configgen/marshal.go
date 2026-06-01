package configgen

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// nebulaConfig is the internal typed-struct representation of a Nebula agent
// config.yml. It exists so Generate can marshal through gopkg.in/yaml.v3
// instead of string-interpolating into a text/template, so structural-break
// characters (CR/LF, control chars, ", :, #) in operator-controlled fields
// can never escape into the YAML structure regardless of what upstream
// validators allow. Defense-in-depth on top of input validation (GHSA-7hp6,
// issue #126).
//
// Operator-controlled scalars use the safeString type rather than a bare
// string: yaml.v3's default style does not round-trip every value (a
// multi-line value such as "\t\n" is emitted as a literal block whose tab the
// parser then rejects), and safeString forces a style that does. literalString
// guards the inline-PEM fields the same way for their readable block form.
type nebulaConfig struct {
	PKI           pkiSection                  `yaml:"pki"`
	StaticHostMap map[safeString][]safeString `yaml:"static_host_map"`
	Lighthouse    lighthouseSection           `yaml:"lighthouse"`
	Listen        listenSection               `yaml:"listen"`
	Punchy        punchySection               `yaml:"punchy"`
	Tun           *tunSection                 `yaml:"tun,omitempty"`
	Relay         *relaySection               `yaml:"relay,omitempty"`
	Logging       loggingSection              `yaml:"logging"`
	Firewall      firewallSection             `yaml:"firewall"`
}

// pkiSection's fields are typed `any` because inline PEMs marshal as
// literal-block scalars (via literalString.MarshalYAML) while path-based
// values are plain strings.
type pkiSection struct {
	CA   any `yaml:"ca"`
	Cert any `yaml:"cert"`
	Key  any `yaml:"key"`
}

// literalString marshals the inline PEM blocks as a YAML literal-block scalar
// (|) when that round-trips, so the multi-line content stays readable.
type literalString string

func (l literalString) MarshalYAML() (any, error) {
	n := &yaml.Node{Kind: yaml.ScalarNode, Value: string(l)}
	// Only request literal-block style for content we know parses back
	// identically. yaml.v3 honors an explicit LiteralStyle even for content
	// the YAML parser then rejects — e.g. a line beginning with a tab or
	// space, emitted verbatim under a block indent the parser reads as broken
	// indentation ("found a tab character where an indentation space is
	// expected"). For anything not literal-safe we leave Style unset so the
	// encoder picks a representation that does round-trip (double-quoted),
	// which the Nebula config loader parses identically. Well-formed PEM
	// blocks are literal-safe and keep their readable multi-line form.
	if literalBlockSafe(string(l)) {
		n.Style = yaml.LiteralStyle
	}
	return n, nil
}

// literalBlockSafe reports whether s can be emitted as a YAML literal-block
// scalar and parsed back identically. It is deliberately conservative: a false
// negative only costs prettiness (the value is double-quoted instead), while a
// false positive emits YAML the agent cannot reload. A line is literal-safe
// when it is non-empty, has no leading or trailing space, and contains only
// printable ASCII (0x20–0x7E) — which excludes tabs, CR, and other control
// bytes. A single trailing newline (the block-chomping marker) is allowed.
func literalBlockSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, line := range strings.Split(strings.TrimSuffix(s, "\n"), "\n") {
		if line == "" {
			return false
		}
		if line[0] == ' ' || line[len(line)-1] == ' ' {
			return false
		}
		for i := 0; i < len(line); i++ {
			if c := line[i]; c < 0x20 || c > 0x7e {
				return false
			}
		}
	}
	return true
}

// safeString marshals an operator-controlled scalar so it always round-trips
// through the YAML parser. yaml.v3's encoder auto-selects a literal/folded
// block style for multi-line strings and emits their content verbatim under
// the block indent; a line that begins with a tab or space (e.g. "\t\n") then
// re-parses as broken indentation ("found a tab character where an indentation
// space is expected"). Double-quoted style escapes every byte and round-trips
// for any string, so force it for multi-line values; single-line values keep
// the encoder's default (plain, or auto-quoted for ambiguous scalars like
// "0"), staying readable. This is the plain-string counterpart to
// literalString, which guards the inline-PEM fields (GHSA-7hp6, issue #126).
type safeString string

func (s safeString) MarshalYAML() (any, error) {
	n := &yaml.Node{Kind: yaml.ScalarNode, Value: string(s)}
	if strings.Contains(string(s), "\n") {
		n.Style = yaml.DoubleQuotedStyle
	}
	return n, nil
}

type lighthouseSection struct {
	AmLighthouse bool         `yaml:"am_lighthouse"`
	Hosts        []safeString `yaml:"hosts,omitempty"`
}

type listenSection struct {
	Host safeString `yaml:"host"`
	Port int        `yaml:"port"`
}

type punchySection struct {
	Punch bool `yaml:"punch"`
}

type tunSection struct {
	Dev          safeString    `yaml:"dev,omitempty"`
	MTU          int           `yaml:"mtu,omitempty"`
	UnsafeRoutes []unsafeRoute `yaml:"unsafe_routes,omitempty"`
}

type unsafeRoute struct {
	Route safeString `yaml:"route"`
	Via   safeString `yaml:"via"`
}

type relaySection struct {
	AmRelay bool         `yaml:"am_relay,omitempty"`
	Relays  []safeString `yaml:"relays,omitempty"`
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
	Port  safeString `yaml:"port"`
	Proto safeString `yaml:"proto"`
	Group safeString `yaml:"group,omitempty"`
	Host  safeString `yaml:"host,omitempty"`
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
			CA:   safeString(input.CACertPath),
			Cert: safeString(input.CertPath),
			Key:  safeString(input.KeyPath),
		}
	}

	cfg.StaticHostMap = map[safeString][]safeString{}
	if input.IsLighthouse {
		cfg.Lighthouse = lighthouseSection{AmLighthouse: true}
	} else {
		var hosts []safeString
		for _, lh := range input.Lighthouses {
			for _, ip := range lh.NebulaIPs {
				cfg.StaticHostMap[safeString(ip)] = []safeString{safeString(lh.PublicAddr)}
				hosts = append(hosts, safeString(ip))
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
	cfg.Listen = listenSection{Host: safeString(listenHost), Port: listenPort}

	punch := true
	if input.PunchyOverride != nil {
		punch = *input.PunchyOverride
	}
	cfg.Punchy = punchySection{Punch: punch}

	if input.MTU != 0 || input.TunDevice != "" || len(input.UnsafeRoutes) > 0 {
		ts := &tunSection{Dev: safeString(input.TunDevice), MTU: input.MTU}
		for _, r := range input.UnsafeRoutes {
			ts.UnsafeRoutes = append(ts.UnsafeRoutes, unsafeRoute{
				Route: safeString(r.Route),
				Via:   safeString(r.Via),
			})
		}
		cfg.Tun = ts
	}

	if input.IsRelay {
		cfg.Relay = &relaySection{AmRelay: true}
	} else if len(input.Relays) > 0 {
		relays := make([]safeString, len(input.Relays))
		for i, r := range input.Relays {
			relays[i] = safeString(r)
		}
		cfg.Relay = &relaySection{Relays: relays}
	}

	cfg.Firewall.Outbound = mapFirewallRules(input.FirewallOutbound)
	cfg.Firewall.Inbound = mapFirewallRules(input.FirewallInbound)

	return cfg
}

func mapFirewallRules(in []FirewallRule) []firewallRule {
	out := make([]firewallRule, 0, len(in))
	for _, r := range in {
		fr := firewallRule{Port: safeString(r.Port), Proto: safeString(r.Proto)}
		if r.Group == "any" {
			fr.Host = "any"
		} else {
			fr.Group = safeString(r.Group)
		}
		out = append(out, fr)
	}
	return out
}
