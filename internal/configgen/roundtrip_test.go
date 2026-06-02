package configgen

import (
	"strings"
	"testing"

	nebcfg "github.com/slackhq/nebula/config"
)

// roundTripValues are operator-controlled strings that a bare/unquoted YAML
// scalar would silently retype or that break the YAML structure outright:
//
//   - "0"/"true" — re-parse as int/bool when emitted bare,
//   - "null"/"~" — re-parse as null,
//   - ""         — re-parses as null,
//   - "<<"       — the YAML merge-key indicator; as a static_host_map key the
//     loader rejects it ("map merge requires map or sequence of maps"),
//   - "\t\n"     — the original #176 crasher: emitted under a block style whose
//     leading tab the parser rejects,
//   - "a:b"/"# x" — colon/comment bytes that would break out of plain style.
//
// safeString.MarshalYAML must make every one of them read back unchanged
// through Nebula's own loader.
var roundTripValues = []string{"0", "true", "null", "~", "", "<<", "\t\n", "a:b", "# x"}

// baseRoundTripInput is a regular-host input built through the same wiring the
// fuzzer drives (fuzzGeneratorInput), so these focused checks can't drift from
// what FuzzGenerate actually exercises.
func baseRoundTripInput() GeneratorInput {
	return fuzzGeneratorInput(
		"web-1", "192.168.100.10", "192.168.100.1", "203.0.113.10:4242",
		"0.0.0.0", "", "any", "icmp", "admin",
		0, 0, false, false, true, false, "")
}

func loadGenerated(t *testing.T, in GeneratorInput) *nebcfg.C {
	t.Helper()
	out, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var c nebcfg.C
	if err := c.LoadString(string(out)); err != nil {
		t.Fatalf("config.LoadString rejected generated config: %v\n--- config ---\n%s", err, out)
	}
	return &c
}

// TestGenerate_SafeStringRoundTrip pushes the ambiguous and structure-breaking
// values above through every operator-controlled safeString field and asserts
// they survive a round-trip through Nebula's own config loader unchanged — the
// guarantee safeString makes "for any string". It complements FuzzGenerate,
// whose type-preserving invariant only covers the non-safeString scalars
// (am_lighthouse / punchy.punch / listen.port), so a regression on a
// safeString field would slip past the fuzzer green.
func TestGenerate_SafeStringRoundTrip(t *testing.T) {
	for _, v := range roundTripValues {
		t.Run("listen.host="+quoteName(v), func(t *testing.T) {
			if v == "" {
				t.Skip("generator substitutes 0.0.0.0 for an empty listen host before it reaches safeString")
			}
			in := baseRoundTripInput()
			in.ListenHost = v
			c := loadGenerated(t, in)
			if got := c.GetString("listen.host", "\x00miss"); got != v {
				t.Errorf("listen.host: got %q want %q", got, v)
			}
		})

		t.Run("static_host_map_key="+quoteName(v), func(t *testing.T) {
			in := baseRoundTripInput()
			in.Lighthouses = []LighthouseInfo{{NebulaIPs: []string{v}, PublicAddr: "203.0.113.10:4242"}}
			c := loadGenerated(t, in)
			m, ok := c.Get("static_host_map").(map[string]any)
			if !ok {
				t.Fatalf("static_host_map missing/wrong type: %T", c.Get("static_host_map"))
			}
			if _, present := m[v]; !present {
				t.Errorf("static_host_map key %q dropped; got keys %v", v, keysOf(m))
			}
		})

		t.Run("static_host_map_value="+quoteName(v), func(t *testing.T) {
			in := baseRoundTripInput()
			in.Lighthouses = []LighthouseInfo{{NebulaIPs: []string{"192.168.100.1"}, PublicAddr: v}}
			c := loadGenerated(t, in)
			m, _ := c.Get("static_host_map").(map[string]any)
			vals, ok := m["192.168.100.1"].([]any)
			if !ok || len(vals) != 1 {
				t.Fatalf("static_host_map value missing: %#v", m["192.168.100.1"])
			}
			if got := mustString(t, vals[0]); got != v {
				t.Errorf("static_host_map value: got %q want %q", got, v)
			}
		})

		t.Run("firewall.port="+quoteName(v), func(t *testing.T) {
			in := baseRoundTripInput()
			in.FirewallInbound = []FirewallRule{{Port: v, Proto: "tcp", Group: "admin"}}
			c := loadGenerated(t, in)
			rule := firstInbound(t, c)
			// The point of the !!str tag: a port like "22" stays a string
			// instead of re-parsing as the int 22.
			if got := mustString(t, rule["port"]); got != v {
				t.Errorf("firewall.inbound[0].port: got %q want %q", got, v)
			}
		})

		t.Run("relay.relays="+quoteName(v), func(t *testing.T) {
			in := baseRoundTripInput()
			in.Relays = []string{v}
			c := loadGenerated(t, in)
			rs, ok := c.Get("relay.relays").([]any)
			if !ok || len(rs) != 1 {
				t.Fatalf("relay.relays missing: %#v", c.Get("relay.relays"))
			}
			if got := mustString(t, rs[0]); got != v {
				t.Errorf("relay.relays[0]: got %q want %q", got, v)
			}
		})

		t.Run("unsafe_routes="+quoteName(v), func(t *testing.T) {
			in := baseRoundTripInput()
			in.UnsafeRoutes = []AdvancedUnsafeRoute{{Route: v, Via: v}}
			c := loadGenerated(t, in)
			routes, ok := c.Get("tun.unsafe_routes").([]any)
			if !ok || len(routes) != 1 {
				t.Fatalf("tun.unsafe_routes missing: %#v", c.Get("tun.unsafe_routes"))
			}
			r, _ := routes[0].(map[string]any)
			if got := mustString(t, r["route"]); got != v {
				t.Errorf("unsafe_routes[0].route: got %q want %q", got, v)
			}
			if got := mustString(t, r["via"]); got != v {
				t.Errorf("unsafe_routes[0].via: got %q want %q", got, v)
			}
		})

		t.Run("pki_path="+quoteName(v), func(t *testing.T) {
			in := baseRoundTripInput()
			in.CACertPath = v
			c := loadGenerated(t, in)
			if got := c.GetString("pki.ca", "\x00miss"); got != v {
				t.Errorf("pki.ca: got %q want %q", got, v)
			}
		})
	}
}

// TestGenerate_MultilineStaysDoubleQuoted pins the rendering, not just the
// round-trip: a multi-line operator value must be emitted double-quoted on a
// single line (every byte escaped), never as a literal/explicit-key block that
// would re-emit the raw tab the parser rejects.
func TestGenerate_MultilineStaysDoubleQuoted(t *testing.T) {
	in := baseRoundTripInput()
	in.ListenHost = "\t\n"
	out, err := Generate(in)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `host: "\t\n"`) {
		t.Errorf("multi-line host not double-quoted on one line:\n%s", s)
	}
	if strings.Contains(s, "host: |") || strings.Contains(s, "host: >") {
		t.Errorf("multi-line host emitted as a block scalar:\n%s", s)
	}
}

func firstInbound(t *testing.T, c *nebcfg.C) map[string]any {
	t.Helper()
	inb, ok := c.Get("firewall.inbound").([]any)
	if !ok || len(inb) == 0 {
		t.Fatalf("firewall.inbound missing: %#v", c.Get("firewall.inbound"))
	}
	rule, ok := inb[0].(map[string]any)
	if !ok {
		t.Fatalf("firewall.inbound[0] wrong type: %T", inb[0])
	}
	return rule
}

// mustString fails the test if v re-parsed as a non-string (e.g. "22" → int 22,
// "true" → bool), which is itself the round-trip regression these tests guard.
func mustString(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("value retyped to %T (%v); expected a string", v, v)
	}
	return s
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// quoteName renders a subtest-name suffix that stays readable for the control
// characters in roundTripValues (a raw "\t\n" would mangle test output).
func quoteName(s string) string {
	r := strings.NewReplacer("\t", `\t`, "\n", `\n`, " ", "_")
	return r.Replace(s)
}
