package hostdns

import (
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
