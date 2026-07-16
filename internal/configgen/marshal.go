package configgen

import (
	"bytes"
	"fmt"
	"strings"
	"unicode/utf8"

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
// string: marshaling a Go string through a yaml.Node does not round-trip every
// value (a multi-line value such as "\t\n" emits as a block whose tab the
// parser then rejects; an ambiguous value such as "0" or "true" emits bare and
// re-parses as int/bool), and safeString forces a representation that always
// reads back unchanged. literalString guards the inline-PEM fields the same way
// for their readable block form.
type nebulaConfig struct {
	PKI           pkiSection                  `yaml:"pki"`
	StaticHostMap map[safeString][]safeString `yaml:"static_host_map"`
	Lighthouse    lighthouseSection           `yaml:"lighthouse"`
	Listen        listenSection               `yaml:"listen"`
	Punchy        punchySection               `yaml:"punchy"`
	Tun           *tunSection                 `yaml:"tun,omitempty"`
	Tunnels       *tunnelsSection             `yaml:"tunnels,omitempty"`
	Relay         *relaySection               `yaml:"relay,omitempty"`
	Logging       loggingSection              `yaml:"logging"`
	Firewall      firewallSection             `yaml:"firewall"`
	Handshakes    *handshakesSection          `yaml:"handshakes,omitempty"`
	MobileNebula  *mobileNebulaSection        `yaml:"mobile_nebula,omitempty"`
}

// pkiSection's fields are typed `any` because inline PEMs marshal as
// literal-block scalars (via literalString.MarshalYAML) while path-based
// values are plain strings.
type pkiSection struct {
	CA        any          `yaml:"ca"`
	Cert      any          `yaml:"cert"`
	Key       any          `yaml:"key"`
	Blocklist []safeString `yaml:"blocklist,omitempty"`
}

// literalString marshals the inline PEM blocks as a YAML literal-block scalar
// (|) when that round-trips, so the multi-line content stays readable.
type literalString string

func (l literalString) MarshalYAML() (any, error) {
	s := string(l)
	n := &yaml.Node{Kind: yaml.ScalarNode, Value: s}
	switch {
	case literalBlockSafe(s):
		// Well-formed PEM blocks keep their readable multi-line form.
		n.Style = yaml.LiteralStyle
	case utf8.ValidString(s):
		// Not literal-safe but valid UTF-8: force double-quoted, which escapes
		// every byte and round-trips unconditionally. Leaving Style unset is
		// NOT enough — yaml.v3 still picks literal-block style for multi-line
		// content on its own and writes a leading tab/space verbatim under the
		// block indent, which the YAML parser then rejects ("found a tab
		// character where an indentation space is expected", issue #176). This
		// mirrors safeString, the plain-string counterpart.
		n.Style = yaml.DoubleQuotedStyle
	default:
		// Invalid UTF-8: leave the node tagless and styleless so yaml.v3 falls
		// back to a !!binary (base64) node, which round-trips — double-quoted
		// style refuses invalid UTF-8.
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
// through the YAML parser, for any string.
//
// For valid UTF-8 the node is tagged "!!str" so it carries the implicit-string
// resolution a native Go string would. A tagless ScalarNode loses that tag and
// so emits ambiguous scalars bare — "0", "true", "null"/"~" and "" would
// re-parse as int, bool and null rather than as their original string. The tag
// restores the encoder's default rendering: plain when the value is unambiguous
// (readable), auto-quoted only when bare emission would retype it. Invalid
// UTF-8 is left tagless on purpose: yaml.v3 refuses to marshal invalid UTF-8
// under an explicit "!!str" tag, so we let the encoder fall back to a "!!binary"
// (base64) node, exactly as a native Go string would — that round-trips too.
//
// Two cases the tag alone does not cover, so force double-quoted style — which
// escapes every byte and round-trips unconditionally:
//
//   - Multi-line values. yaml.v3 emits a multi-line scalar as a block (literal
//     for a mapping value, an explicit-key "? |" block for a mapping key) and
//     writes the content verbatim under the block indent; a line beginning
//     with a tab or space (e.g. "\t\n") then re-parses as broken indentation
//     ("found a tab character where an indentation space is expected"). This
//     was the original crasher (issue #176).
//   - "<<". As a static_host_map key (safeString is also the map's key type)
//     bare "<<" is the YAML merge indicator, so the loader rejects it with
//     "map merge requires map or sequence of maps as the value". Quoting it
//     keeps it a literal string key.
//
// This is the plain-string counterpart to literalString, which guards the
// inline-PEM fields (GHSA-7hp6, issue #126).
type safeString string

func (s safeString) MarshalYAML() (any, error) {
	n := &yaml.Node{Kind: yaml.ScalarNode, Value: string(s)}
	if utf8.ValidString(string(s)) {
		n.Tag = "!!str"
		if strings.Contains(string(s), "\n") || string(s) == "<<" {
			n.Style = yaml.DoubleQuotedStyle
		}
	}
	return n, nil
}

type lighthouseSection struct {
	AmLighthouse    bool                   `yaml:"am_lighthouse"`
	Hosts           []safeString           `yaml:"hosts,omitempty"`
	Interval        int                    `yaml:"interval,omitempty"`
	LocalAllowList  *localAllowListSection `yaml:"local_allow_list,omitempty"`
	RemoteAllowList map[safeString]bool    `yaml:"remote_allow_list,omitempty"`
}

type localAllowListSection struct {
	Interfaces map[safeString]bool `yaml:"interfaces"`
}

type listenSection struct {
	Host safeString `yaml:"host"`
	Port int        `yaml:"port"`
}

type punchySection struct {
	Punch   bool  `yaml:"punch"`
	Respond *bool `yaml:"respond,omitempty"`
}

type tunSection struct {
	Dev                safeString    `yaml:"dev,omitempty"`
	DropLocalBroadcast *bool         `yaml:"drop_local_broadcast,omitempty"`
	DropMulticast      *bool         `yaml:"drop_multicast,omitempty"`
	MTU                int           `yaml:"mtu,omitempty"`
	UnsafeRoutes       []unsafeRoute `yaml:"unsafe_routes,omitempty"`
}

type tunnelsSection struct {
	DropInactive      bool       `yaml:"drop_inactive"`
	InactivityTimeout safeString `yaml:"inactivity_timeout"`
}

type unsafeRoute struct {
	Route safeString `yaml:"route"`
	Via   safeString `yaml:"via"`
}

type relaySection struct {
	AmRelay   *bool        `yaml:"am_relay,omitempty"`
	Relays    []safeString `yaml:"relays,omitempty"`
	UseRelays *bool        `yaml:"use_relays,omitempty"`
}

type loggingSection struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type firewallSection struct {
	OutboundAction safeString     `yaml:"outbound_action,omitempty"`
	InboundAction  safeString     `yaml:"inbound_action,omitempty"`
	Outbound       []firewallRule `yaml:"outbound"`
	Inbound        []firewallRule `yaml:"inbound"`
}

type handshakesSection struct {
	Retries     int        `yaml:"retries"`
	TryInterval safeString `yaml:"try_interval"`
}

type mobileNebulaSection struct {
	DNSResolvers []safeString `yaml:"dns_resolvers"`
	MatchDomains []safeString `yaml:"match_domains"`
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
			CA:        literalString(input.CACertPEM),
			Cert:      literalString(input.CertPEM),
			Key:       literalString(input.KeyPEM),
			Blocklist: toSafeStrings(input.Blocklist),
		}
	} else {
		cfg.PKI = pkiSection{
			CA:        safeString(input.CACertPath),
			Cert:      safeString(input.CertPath),
			Key:       safeString(input.KeyPath),
			Blocklist: toSafeStrings(input.Blocklist),
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
		if input.Mobile != nil {
			listenHost = "[::]"
		} else {
			listenHost = "0.0.0.0"
		}
	}
	listenPort := input.ListenPort
	if listenPort == 0 && input.IsLighthouse && input.Mobile == nil {
		listenPort = 4242
	}
	cfg.Listen = listenSection{Host: safeString(listenHost), Port: listenPort}

	punch := true
	if input.PunchyOverride != nil {
		punch = *input.PunchyOverride
	}
	cfg.Punchy = punchySection{Punch: punch}
	if input.Mobile != nil {
		cfg.Punchy.Respond = boolPtr(false)
	}

	if input.Mobile != nil || input.MTU != 0 || input.TunDevice != "" || len(input.UnsafeRoutes) > 0 {
		dev := input.TunDevice
		mtu := input.MTU
		if input.Mobile != nil {
			if dev == "" {
				dev = "nebula1"
			}
			if mtu == 0 {
				mtu = 1300
			}
		}
		ts := &tunSection{Dev: safeString(dev), MTU: mtu}
		if input.Mobile != nil {
			ts.DropLocalBroadcast = boolPtr(true)
			ts.DropMulticast = boolPtr(true)
		}
		for _, r := range input.UnsafeRoutes {
			ts.UnsafeRoutes = append(ts.UnsafeRoutes, unsafeRoute{
				Route: safeString(r.Route),
				Via:   safeString(r.Via),
			})
		}
		cfg.Tun = ts
	}

	if input.IsRelay {
		cfg.Relay = &relaySection{AmRelay: boolPtr(true)}
	} else if input.Mobile != nil || len(input.Relays) > 0 {
		relays := make([]safeString, len(input.Relays))
		for i, r := range input.Relays {
			relays[i] = safeString(r)
		}
		cfg.Relay = &relaySection{Relays: relays}
		if input.Mobile != nil {
			cfg.Relay.AmRelay = boolPtr(false)
			cfg.Relay.UseRelays = boolPtr(true)
		}
	}

	cfg.Firewall.Outbound = mapFirewallRules(input.FirewallOutbound)
	cfg.Firewall.Inbound = mapFirewallRules(input.FirewallInbound)
	if input.Mobile != nil {
		applyMobileProfile(&cfg, *input.Mobile)
	}

	return cfg
}

func applyMobileProfile(cfg *nebulaConfig, profile MobileProfile) {
	cfg.Handshakes = &handshakesSection{Retries: 10, TryInterval: "100ms"}
	cfg.Lighthouse.Interval = 60
	cfg.Lighthouse.LocalAllowList = &localAllowListSection{Interfaces: map[safeString]bool{
		"docker.*":   false,
		"nebula1":    false,
		"podman.*":   false,
		"tailscale0": false,
		"tun.*":      false,
		"utun.*":     false,
		"veth.*":     false,
	}}
	cfg.Lighthouse.RemoteAllowList = mobileRemoteAllowList(profile.AllowPrivateRemotes)
	cfg.Tunnels = &tunnelsSection{DropInactive: true, InactivityTimeout: "10m"}
	cfg.Firewall.InboundAction = "drop"
	cfg.Firewall.OutboundAction = "drop"
	if len(profile.DNSResolvers) > 0 {
		cfg.MobileNebula = &mobileNebulaSection{
			DNSResolvers: toSafeStrings(profile.DNSResolvers),
			MatchDomains: toSafeStringsPreserveEmpty(profile.MatchDomains),
		}
	}
}

func mobileRemoteAllowList(allowPrivate bool) map[safeString]bool {
	allowList := map[safeString]bool{
		"0.0.0.0/0":      true,
		"::/0":           true,
		"127.0.0.0/8":    false,
		"::1/128":        false,
		"169.254.0.0/16": false,
		"fe80::/10":      false,
	}
	if !allowPrivate {
		allowList["10.0.0.0/8"] = false
		allowList["100.64.0.0/10"] = false
		allowList["172.16.0.0/12"] = false
		allowList["192.168.0.0/16"] = false
		allowList["fc00::/7"] = false
	}
	return allowList
}

func boolPtr(v bool) *bool {
	return &v
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

func toSafeStrings(in []string) []safeString {
	if len(in) == 0 {
		return nil
	}
	out := make([]safeString, len(in))
	for i, s := range in {
		out[i] = safeString(s)
	}
	return out
}

func toSafeStringsPreserveEmpty(in []string) []safeString {
	if len(in) == 0 {
		return []safeString{}
	}
	return toSafeStrings(in)
}
