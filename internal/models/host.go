package models

import "time"

type HostStatus string

const (
	HostStatusPending  HostStatus = "pending"
	HostStatusEnrolled HostStatus = "enrolled"
	HostStatusBlocked  HostStatus = "blocked"
)

type HostRole string

const (
	HostRoleHost       HostRole = "host"
	HostRoleLighthouse HostRole = "lighthouse"
	HostRoleRelay      HostRole = "relay"
)

// ValidRole reports whether r is a known host role or empty (meaning "use default").
func ValidRole(r HostRole) bool {
	switch r {
	case "", HostRoleHost, HostRoleLighthouse, HostRoleRelay:
		return true
	default:
		return false
	}
}

type Host struct {
	ID              string         `json:"id"`
	NetworkID       string         `json:"network_id"`
	Name            string         `json:"name"`
	NebulaIP        string         `json:"nebula_ip"`
	Groups          []string       `json:"groups"`
	Role            HostRole       `json:"role"`
	IsLighthouse    bool           `json:"is_lighthouse"`
	IsRelay         bool           `json:"is_relay"`
	PublicIP        string         `json:"public_ip,omitempty"`
	ListenPort      int            `json:"listen_port,omitempty"`
	Status          HostStatus     `json:"status"`
	CertFingerprint string         `json:"cert_fingerprint,omitempty"`
	CertExpiresAt   *time.Time     `json:"cert_expires_at,omitempty"`
	LastSeenAt      *time.Time     `json:"last_seen_at,omitempty"`
	Advanced        *HostAdvanced  `json:"advanced,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// UnsafeRoute is a single "unsafe route" entry: traffic for `Route` is sent
// through the host with Nebula IP `Via`. See Nebula's tun.unsafe_routes.
type UnsafeRoute struct {
	Route string `json:"route" yaml:"route"` // CIDR
	Via   string `json:"via" yaml:"via"`     // Nebula IP of the gateway host
}

// HostAdvanced groups optional per-host overrides for the rendered Nebula
// config. All fields are optional. A field set to its zero value means
// "inherit network default"; a field set to a non-zero value overrides.
//
// Punchy is a tri-state pointer so an operator can explicitly disable
// hole-punching for a host (false) without it being indistinguishable from
// "not set".
type HostAdvanced struct {
	Punchy       *bool         `json:"punchy,omitempty" yaml:"punchy,omitempty"`
	ListenHost   string        `json:"listen_host,omitempty" yaml:"listen_host,omitempty"`
	MTU          int           `json:"mtu,omitempty" yaml:"mtu,omitempty"`
	TunDevice    string        `json:"tun_device,omitempty" yaml:"tun_device,omitempty"`
	UnsafeRoutes []UnsafeRoute `json:"unsafe_routes,omitempty" yaml:"unsafe_routes,omitempty"`
}
