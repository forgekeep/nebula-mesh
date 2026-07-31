package web

import (
	"slices"
	"testing"
)

func TestSplitCommaList(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []string
	}{
		{"empty", "", nil},
		{"blank", "   ", nil},
		{"single", "web", []string{"web"}},
		{"comma separated", "web,prod", []string{"web", "prod"}},
		{"comma space separated", "web, prod", []string{"web", "prod"}},
		{"one per line", "10.0.0.0/8\n192.168.1.0/24", []string{"10.0.0.0/8", "192.168.1.0/24"}},
		{"crlf line endings", "web\r\nprod", []string{"web", "prod"}},
		{"trailing comma", "web,prod,", []string{"web", "prod"}},
		{"double comma", "web,,prod", []string{"web", "prod"}},
		{"surrounding whitespace", "  web , prod  ", []string{"web", "prod"}},

		// A group name may contain a space — the API accepts any non-blank
		// name up to 64 chars, and the edit form round-trips groups through
		// strings.Join. Splitting on whitespace here would silently turn one
		// group into two on every save, changing a certificate-bound field.
		{"name with an internal space", "my group", []string{"my group"}},
		{"names with internal spaces", "my group, other group", []string{"my group", "other group"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := splitCommaList(tc.value)
			if !slices.Equal(got, tc.want) {
				t.Errorf("splitCommaList(%q) = %#v, want %#v", tc.value, got, tc.want)
			}
		})
	}
}
