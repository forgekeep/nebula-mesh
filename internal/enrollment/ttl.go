// Package enrollment holds the enrollment-token lifetime policy shared by the
// API and Web UI host-creation paths. Keeping the resolver in one place stops
// the two paths from drifting: GHSA-g4x6-jcvr-9m3g was exactly such a drift —
// the API honored the configured TTL while the Web UI hardcoded 24h.
package enrollment

import (
	"context"
	"time"
)

// DefaultTokenTTL is the fallback lifetime applied when neither a per-network
// override nor a server-level default is configured (ADR 0004 §7.1).
const DefaultTokenTTL = 24 * time.Hour

// NetworkConfigGetter reads a single per-network configuration value. Both
// store.Store and *store.SQLiteStore satisfy it via GetNetworkConfig, so the
// resolver stays decoupled from the full store surface.
type NetworkConfigGetter interface {
	GetNetworkConfig(ctx context.Context, networkID, key string) (string, error)
}

// TokenTTL resolves the enrollment-token TTL for networkID. Order of
// precedence: the per-network `enrollment_token_ttl` value in network_config,
// then the server-level defaultTTL, then DefaultTokenTTL. A non-positive
// defaultTTL is treated as unset. A missing, empty, unparseable, or
// non-positive per-network value falls through to the next level.
func TokenTTL(ctx context.Context, g NetworkConfigGetter, defaultTTL time.Duration, networkID string) time.Duration {
	if networkID != "" {
		v, err := g.GetNetworkConfig(ctx, networkID, "enrollment_token_ttl")
		if err == nil && v != "" {
			if d, perr := time.ParseDuration(v); perr == nil && d > 0 {
				return d
			}
		}
	}
	if defaultTTL > 0 {
		return defaultTTL
	}
	return DefaultTokenTTL
}
