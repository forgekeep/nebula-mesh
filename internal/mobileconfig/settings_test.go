package mobileconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	t.Parallel()

	settings := Default()

	assert.NotNil(t, settings.DNSResolvers)
	assert.Empty(t, settings.DNSResolvers)
	assert.NotNil(t, settings.MatchDomains)
	assert.Empty(t, settings.MatchDomains)
	assert.True(t, settings.AllowPrivateRemotes)
	assert.Equal(t, "mobile_config", StoreKey)
}

func TestDecodeNormalizesSettings(t *testing.T) {
	t.Parallel()

	settings, err := Decode(`{
		"dns_resolvers": [" 10.0.0.53 ", "2001:0db8::53"],
		"match_domains": [" corp.example "],
		"allow_private_remotes": false
	}`)
	require.NoError(t, err)

	assert.Equal(t, []string{"10.0.0.53", "2001:db8::53"}, settings.DNSResolvers)
	assert.Equal(t, []string{"corp.example"}, settings.MatchDomains)
	assert.False(t, settings.AllowPrivateRemotes)
}

func TestDecodeRejectsInvalidSettings(t *testing.T) {
	t.Parallel()

	manyResolvers := make([]string, 17)
	for i := range manyResolvers {
		manyResolvers[i] = "192.0.2." + string(rune('1'+i))
	}
	manyDomains := make([]string, 65)
	for i := range manyDomains {
		manyDomains[i] = "domain" + string(rune('a'+i)) + ".example"
	}

	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name:    "missing dns resolvers",
			raw:     `{"match_domains":[],"allow_private_remotes":true}`,
			wantErr: "dns_resolvers is required",
		},
		{
			name:    "missing match domains",
			raw:     `{"dns_resolvers":[],"allow_private_remotes":true}`,
			wantErr: "match_domains is required",
		},
		{
			name:    "missing private policy",
			raw:     `{"dns_resolvers":[],"match_domains":[]}`,
			wantErr: "allow_private_remotes is required",
		},
		{
			name:    "unknown field",
			raw:     `{"dns_resolvers":[],"match_domains":[],"allow_private_remotes":true,"extra":1}`,
			wantErr: "unknown field",
		},
		{
			name:    "trailing json",
			raw:     `{"dns_resolvers":[],"match_domains":[],"allow_private_remotes":true}{}`,
			wantErr: "trailing JSON",
		},
		{
			name:    "invalid resolver",
			raw:     `{"dns_resolvers":["dns.example"],"match_domains":[],"allow_private_remotes":true}`,
			wantErr: "dns_resolvers[0]",
		},
		{
			name:    "resolver zone",
			raw:     `{"dns_resolvers":["fe80::1%en0"],"match_domains":[],"allow_private_remotes":true}`,
			wantErr: "zone",
		},
		{
			name:    "duplicate resolver",
			raw:     `{"dns_resolvers":["2001:db8::53","2001:0db8::53"],"match_domains":[],"allow_private_remotes":true}`,
			wantErr: "duplicate",
		},
		{
			name:    "empty domain",
			raw:     `{"dns_resolvers":[],"match_domains":["  "],"allow_private_remotes":true}`,
			wantErr: "match_domains[0]",
		},
		{
			name:    "domain whitespace",
			raw:     `{"dns_resolvers":[],"match_domains":["corp example"],"allow_private_remotes":true}`,
			wantErr: "whitespace",
		},
		{
			name:    "duplicate domain",
			raw:     `{"dns_resolvers":[],"match_domains":["Corp.Example","corp.example"],"allow_private_remotes":true}`,
			wantErr: "duplicate",
		},
		{
			name:    "domain too long",
			raw:     settingsJSON(t, nil, []string{strings.Repeat("a", 254)}, true),
			wantErr: "253",
		},
		{
			name:    "too many resolvers",
			raw:     settingsJSON(t, manyResolvers, nil, true),
			wantErr: "at most 16",
		},
		{
			name:    "too many domains",
			raw:     settingsJSON(t, nil, manyDomains, true),
			wantErr: "at most 64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := Decode(tt.raw)
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func settingsJSON(t *testing.T, resolvers, domains []string, allowPrivate bool) string {
	t.Helper()

	if resolvers == nil {
		resolvers = []string{}
	}
	if domains == nil {
		domains = []string{}
	}
	b, err := json.Marshal(Settings{
		DNSResolvers:        resolvers,
		MatchDomains:        domains,
		AllowPrivateRemotes: allowPrivate,
	})
	require.NoError(t, err)
	return string(b)
}
