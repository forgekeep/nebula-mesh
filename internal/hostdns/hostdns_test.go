package hostdns

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestDecode(t *testing.T) {
	got, err := Decode(`{"nameservers":[" 10.0.0.53 ","fd00::53"],"match_domains":["Mesh.Example.com."],"search_domains":["web.mesh.example.com"]}`)
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{
		Nameservers:   []string{"10.0.0.53", "fd00::53"},
		MatchDomains:  []string{"mesh.example.com"},
		SearchDomains: []string{"web.mesh.example.com"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Decode = %+v, want %+v", got, want)
	}
	if !got.Enabled() {
		t.Error("Enabled = false with nameservers set")
	}
}

func TestDecode_OffState(t *testing.T) {
	got, err := Decode(`{"nameservers":[],"match_domains":[],"search_domains":[]}`)
	if err != nil || got.Enabled() {
		t.Fatalf("Decode = %+v, %v; want disabled", got, err)
	}
}

func TestDecode_Rejects(t *testing.T) {
	tests := map[string]string{
		`{"nameservers":["10.0.0.53"],"match_domains":["a.example"]}`:                                            "search_domains is required",
		`{"nameservers":["10.0.0.53"],"match_domains":["a.example"],"search_domains":[],"x":1}`:                  "unknown field",
		`{"nameservers":["10.0.0.53"],"match_domains":["a.example"],"search_domains":[]} {}`:                     "trailing JSON",
		`{"nameservers":["dns.example"],"match_domains":["a.example"],"search_domains":[]}`:                      "nameservers[0] must be an IP address",
		`{"nameservers":["fe80::1%eth0"],"match_domains":["a.example"],"search_domains":[]}`:                     "nameservers[0] must be an IP address without a zone",
		`{"nameservers":["10.0.0.53","10.0.0.53"],"match_domains":["a.example"],"search_domains":[]}`:            "nameservers[1] duplicates",
		`{"nameservers":["10.0.0.53"],"match_domains":[],"search_domains":[]}`:                                   "match_domains must list at least one domain",
		`{"nameservers":[],"match_domains":["a.example"],"search_domains":[]}`:                                   "nameservers is required",
		`{"nameservers":["10.0.0.53"],"match_domains":["a.example"],"search_domains":["b.example"]}`:             "search_domains[0] \"b.example\" must fall under",
		`{"nameservers":["10.0.0.53"],"match_domains":["a example"],"search_domains":[]}`:                        "must not contain whitespace",
		`{"nameservers":["10.0.0.53"],"match_domains":["a.example","A.example."],"search_domains":[]}`:           "match_domains[1] duplicates",
		`{"nameservers":["10.0.0.53"],"match_domains":["` + strings.Repeat("a", 254) + `"],"search_domains":[]}`: "must not exceed 253 bytes",
	}
	for raw, want := range tests {
		if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Decode(%s) err = %v, want %q", raw, err, want)
		}
	}
}

// Nebula 1.12 validates the dns stanza with dnsconfig and refuses to start on
// a failure, so the server must reject every value that check rejects.
func TestDecode_RejectsWhatNebulaRejects(t *testing.T) {
	body := func(ns, domain string) string {
		return `{"nameservers":["` + ns + `"],"match_domains":["` + domain + `"],"search_domains":[]}`
	}
	tests := map[string]string{
		body("0.0.0.0", "mesh.example"):                       "nebula would reject",
		body("224.0.0.1", "mesh.example"):                     "nebula would reject",
		body("255.255.255.255", "mesh.example"):               "nebula would reject",
		body("::", "mesh.example"):                            "nebula would reject",
		body("10.0.0.53", "*.mesh.example"):                   "nebula would reject",
		body("10.0.0.53", "a..b"):                             "nebula would reject",
		body("10.0.0.53", "mesh/example"):                     "nebula would reject",
		body("10.0.0.53", "-bad.example"):                     "nebula would reject",
		body("10.0.0.53", strings.Repeat("a", 64)+".example"): "nebula would reject",
		body("10.0.0.53", ".."):                               "must name a domain",
		body("10.0.0.53", "."):                                "must name a domain",
	}
	for raw, want := range tests {
		if _, err := Decode(raw); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Decode(%s) err = %v, want %q", raw, err, want)
		}
	}
}

// A stored value must decode again: the renderer re-reads it for every host.
func TestDecode_StoredValueRoundTrips(t *testing.T) {
	first, err := Decode(`{"nameservers":["10.0.0.53"],"match_domains":["Mesh.Example.."],"search_domains":["_svc.mesh.example"]}`)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Decode(string(raw))
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("re-decode = %+v, %v; want %+v", second, err, first)
	}
}
