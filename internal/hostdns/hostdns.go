// Package hostdns defines the network-scoped split DNS settings rendered into
// Nebula's experimental `dns` stanza (Nebula 1.12+, macOS and Windows). The
// stanza points the host's resolver at the overlay nameservers for the
// listed domains only; redirecting every lookup is not offered.
package hostdns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode"

	"github.com/DefinedNet/dnsconfig"
)

const (
	// StoreKey is the network_config key for the host DNS settings.
	StoreKey = "host_dns"

	maxNameservers = 16
	maxDomains     = 64
	maxDomainBytes = 253
)

// Settings is the split DNS configuration of a network. Empty Nameservers
// turns the stanza off.
type Settings struct {
	Nameservers   []string `json:"nameservers"`
	MatchDomains  []string `json:"match_domains"`
	SearchDomains []string `json:"search_domains"`
}

type wireSettings struct {
	Nameservers   *[]string `json:"nameservers"`
	MatchDomains  *[]string `json:"match_domains"`
	SearchDomains *[]string `json:"search_domains"`
}

// Default is the off state.
func Default() Settings {
	return Settings{Nameservers: []string{}, MatchDomains: []string{}, SearchDomains: []string{}}
}

// Enabled reports whether the stanza is rendered at all.
func (s Settings) Enabled() bool {
	return len(s.Nameservers) > 0
}

// Decode parses and normalizes the JSON representation. Every field is
// required, so a PUT replaces the whole setting.
func Decode(raw string) (Settings, error) {
	var wire wireSettings
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return Settings{}, fmt.Errorf("decode host dns: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return Settings{}, fmt.Errorf("trailing JSON after host dns")
	}
	switch {
	case wire.Nameservers == nil:
		return Settings{}, fmt.Errorf("nameservers is required")
	case wire.MatchDomains == nil:
		return Settings{}, fmt.Errorf("match_domains is required")
	case wire.SearchDomains == nil:
		return Settings{}, fmt.Errorf("search_domains is required")
	}
	return Settings{
		Nameservers:   *wire.Nameservers,
		MatchDomains:  *wire.MatchDomains,
		SearchDomains: *wire.SearchDomains,
	}.Normalize()
}

// Normalize validates settings and returns their canonical form.
func (s Settings) Normalize() (Settings, error) {
	if len(s.Nameservers) > maxNameservers {
		return Settings{}, fmt.Errorf("nameservers must contain at most %d entries", maxNameservers)
	}
	out := Default()
	seen := map[string]bool{}
	addrs := make([]netip.Addr, 0, len(s.Nameservers))
	for i, ns := range s.Nameservers {
		addr, err := netip.ParseAddr(strings.TrimSpace(ns))
		if err != nil || addr.Zone() != "" {
			return Settings{}, fmt.Errorf("nameservers[%d] must be an IP address without a zone", i)
		}
		if seen[addr.String()] {
			return Settings{}, fmt.Errorf("nameservers[%d] duplicates %q", i, addr.String())
		}
		seen[addr.String()] = true
		addrs = append(addrs, addr)
		out.Nameservers = append(out.Nameservers, addr.String())
	}
	var err error
	if out.MatchDomains, err = normalizeDomains("match_domains", s.MatchDomains); err != nil {
		return Settings{}, err
	}
	if out.SearchDomains, err = normalizeDomains("search_domains", s.SearchDomains); err != nil {
		return Settings{}, err
	}
	if !out.Enabled() {
		if len(out.MatchDomains) > 0 || len(out.SearchDomains) > 0 {
			return Settings{}, fmt.Errorf("nameservers is required when match_domains or search_domains is set")
		}
		return out, nil
	}
	// An empty match_domains would send every lookup to the overlay
	// nameservers; only split DNS is offered.
	if len(out.MatchDomains) == 0 {
		return Settings{}, fmt.Errorf("match_domains must list at least one domain")
	}
	for i, search := range out.SearchDomains {
		if !underAny(search, out.MatchDomains) {
			return Settings{}, fmt.Errorf("search_domains[%d] %q must fall under a match_domains entry", i, search)
		}
	}
	// Nebula 1.12 runs the same check on the stanza and refuses to start when
	// it fails, so a setting that passed here but not there would take every
	// host in the network down.
	cfg := dnsconfig.Config{Nameservers: addrs, MatchDomains: out.MatchDomains, SearchDomains: out.SearchDomains}
	if err := cfg.Validate(); err != nil {
		return Settings{}, fmt.Errorf("nebula would reject this host dns: %w", err)
	}
	return out, nil
}

func normalizeDomains(field string, values []string) ([]string, error) {
	if len(values) > maxDomains {
		return nil, fmt.Errorf("%s must contain at most %d entries", field, maxDomains)
	}
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for i, raw := range values {
		value := strings.TrimRight(strings.ToLower(strings.TrimSpace(raw)), ".")
		switch {
		case value == "":
			return nil, fmt.Errorf("%s[%d] must name a domain, not be empty or the root", field, i)
		case len(value) > maxDomainBytes:
			return nil, fmt.Errorf("%s[%d] must not exceed %d bytes", field, i, maxDomainBytes)
		case strings.IndexFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
			return nil, fmt.Errorf("%s[%d] must not contain whitespace or control characters", field, i)
		case seen[value]:
			return nil, fmt.Errorf("%s[%d] duplicates %q", field, i, value)
		}
		seen[value] = true
		out = append(out, value)
	}
	return out, nil
}

// underAny reports whether domain equals or is a subdomain of one of parents.
func underAny(domain string, parents []string) bool {
	for _, p := range parents {
		if domain == p || strings.HasSuffix(domain, "."+p) {
			return true
		}
	}
	return false
}
