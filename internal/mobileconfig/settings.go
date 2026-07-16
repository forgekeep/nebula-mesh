// Package mobileconfig defines network-scoped settings used only when the
// control plane renders a Mobile Nebula bundle.
package mobileconfig

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode"
)

const (
	// StoreKey is the network_config key used for mobile settings.
	StoreKey = "mobile_config"

	maxDNSResolvers = 16
	maxMatchDomains = 64
	maxDomainBytes  = 253
)

// Settings controls Mobile Nebula-specific DNS and endpoint discovery policy.
type Settings struct {
	DNSResolvers        []string `json:"dns_resolvers"`
	MatchDomains        []string `json:"match_domains"`
	AllowPrivateRemotes bool     `json:"allow_private_remotes"`
}

type wireSettings struct {
	DNSResolvers        *[]string `json:"dns_resolvers"`
	MatchDomains        *[]string `json:"match_domains"`
	AllowPrivateRemotes *bool     `json:"allow_private_remotes"`
}

// Default returns settings that preserve existing private-network discovery.
func Default() Settings {
	return Settings{
		DNSResolvers:        []string{},
		MatchDomains:        []string{},
		AllowPrivateRemotes: true,
	}
}

// Decode parses and normalizes the persisted JSON representation.
func Decode(raw string) (Settings, error) {
	var wire wireSettings
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return Settings{}, fmt.Errorf("decode mobile config: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return Settings{}, err
	}
	if wire.DNSResolvers == nil {
		return Settings{}, fmt.Errorf("dns_resolvers is required")
	}
	if wire.MatchDomains == nil {
		return Settings{}, fmt.Errorf("match_domains is required")
	}
	if wire.AllowPrivateRemotes == nil {
		return Settings{}, fmt.Errorf("allow_private_remotes is required")
	}

	return (Settings{
		DNSResolvers:        *wire.DNSResolvers,
		MatchDomains:        *wire.MatchDomains,
		AllowPrivateRemotes: *wire.AllowPrivateRemotes,
	}).Normalize()
}

func ensureJSONEOF(dec *json.Decoder) error {
	var trailing any
	err := dec.Decode(&trailing)
	if err == nil {
		return fmt.Errorf("trailing JSON value")
	}
	if err != io.EOF {
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

// Normalize validates settings and returns their canonical representation.
func (s Settings) Normalize() (Settings, error) {
	if len(s.DNSResolvers) > maxDNSResolvers {
		return Settings{}, fmt.Errorf("dns_resolvers must contain at most %d entries", maxDNSResolvers)
	}
	if len(s.MatchDomains) > maxMatchDomains {
		return Settings{}, fmt.Errorf("match_domains must contain at most %d entries", maxMatchDomains)
	}

	normalized := Settings{
		DNSResolvers:        make([]string, 0, len(s.DNSResolvers)),
		MatchDomains:        make([]string, 0, len(s.MatchDomains)),
		AllowPrivateRemotes: s.AllowPrivateRemotes,
	}

	seenResolvers := make(map[string]struct{}, len(s.DNSResolvers))
	for i, resolver := range s.DNSResolvers {
		addr, err := netip.ParseAddr(strings.TrimSpace(resolver))
		if err != nil {
			return Settings{}, fmt.Errorf("dns_resolvers[%d] must be an IP address: %w", i, err)
		}
		if addr.Zone() != "" {
			return Settings{}, fmt.Errorf("dns_resolvers[%d] must not contain an IPv6 zone", i)
		}
		value := addr.String()
		if _, exists := seenResolvers[value]; exists {
			return Settings{}, fmt.Errorf("dns_resolvers[%d] duplicates %q", i, value)
		}
		seenResolvers[value] = struct{}{}
		normalized.DNSResolvers = append(normalized.DNSResolvers, value)
	}

	seenDomains := make(map[string]struct{}, len(s.MatchDomains))
	for i, domain := range s.MatchDomains {
		value := strings.TrimSpace(domain)
		if value == "" {
			return Settings{}, fmt.Errorf("match_domains[%d] must not be empty", i)
		}
		if len(value) > maxDomainBytes {
			return Settings{}, fmt.Errorf("match_domains[%d] must not exceed %d bytes", i, maxDomainBytes)
		}
		if strings.IndexFunc(value, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) >= 0 {
			return Settings{}, fmt.Errorf("match_domains[%d] must not contain whitespace or control characters", i)
		}
		key := strings.ToLower(value)
		if _, exists := seenDomains[key]; exists {
			return Settings{}, fmt.Errorf("match_domains[%d] duplicates %q", i, value)
		}
		seenDomains[key] = struct{}{}
		normalized.MatchDomains = append(normalized.MatchDomains, value)
	}

	return normalized, nil
}

// Validate reports whether settings can be stored and rendered.
func (s Settings) Validate() error {
	_, err := s.Normalize()
	return err
}
