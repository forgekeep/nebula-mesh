package models

import (
	"errors"
	"strings"
	"time"
)

type HostStatus string

const (
	HostStatusPending   HostStatus = "pending"
	HostStatusEnrolled  HostStatus = "enrolled"
	HostStatusBlocked   HostStatus = "blocked"
	HostStatusImporting HostStatus = "importing"
)

type HostRole string

const (
	HostRoleHost            HostRole = "host"
	HostRoleLighthouse      HostRole = "lighthouse"
	HostRoleRelay           HostRole = "relay"
	HostRoleLighthouseRelay HostRole = "lighthouse+relay"
)

// ValidRole reports whether r is a known host role or empty (meaning "use default").
func ValidRole(r HostRole) bool {
	switch r {
	case "", HostRoleHost, HostRoleLighthouse, HostRoleRelay, HostRoleLighthouseRelay:
		return true
	default:
		return false
	}
}

// Lighthouse reports whether the role includes lighthouse duty.
func (r HostRole) Lighthouse() bool {
	return r == HostRoleLighthouse || r == HostRoleLighthouseRelay
}

// Relay reports whether the role includes relay duty.
func (r HostRole) Relay() bool {
	return r == HostRoleRelay || r == HostRoleLighthouseRelay
}

type HostKind string

const (
	HostKindAgent  HostKind = "agent"
	HostKindMobile HostKind = "mobile"
)

// ValidKind reports whether k is a known host kind.
func ValidKind(k HostKind) bool {
	switch k {
	case HostKindAgent, HostKindMobile:
		return true
	default:
		return false
	}
}

type HostVariant string

const (
	HostVariantNone    HostVariant = ""
	HostVariantIOS     HostVariant = "ios"
	HostVariantAndroid HostVariant = "android"
)

// ValidVariant reports whether v is a known host variant (including empty).
func ValidVariant(v HostVariant) bool {
	switch v {
	case HostVariantNone, HostVariantIOS, HostVariantAndroid:
		return true
	default:
		return false
	}
}

// ErrMobileRoleRestricted is returned when a mobile host is assigned a role
// other than host (e.g., lighthouse or relay). Mobile Nebula clients cannot
// reliably listen on a public socket in the background, so these roles are
// not supported for mobile hosts.
var ErrMobileRoleRestricted = errors.New("mobile hosts must have role=host (lighthouse/relay not supported)")

// ErrMobileVariantRequired is returned when a mobile host is created without
// specifying a variant (ios or android). The variant field is required to
// distinguish mobile client types.
var ErrMobileVariantRequired = errors.New("mobile hosts must have variant set to ios or android")

// ValidateMobileConstraints enforces role and variant constraints for mobile hosts.
// For kind=mobile, role must be host (or empty) and variant must be ios or android.
// For kind=agent, no constraints are applied (returns nil).
func ValidateMobileConstraints(kind HostKind, variant HostVariant, role HostRole) error {
	if kind != HostKindMobile {
		return nil
	}

	if role != "" && role != HostRoleHost {
		return ErrMobileRoleRestricted
	}

	if variant == HostVariantNone {
		return ErrMobileVariantRequired
	}

	return nil
}

// ErrRoleRequiresPublicIP is returned when a host with role=lighthouse or
// role=relay is created without a non-empty public_ip. Such a host would
// never be advertised to peers (see internal/api/enroll.go where
// static_host_map / lighthouse.hosts only include hosts whose PublicIP is
// set), so accept-and-silently-drop is replaced with reject-at-create.
var ErrRoleRequiresPublicIP = errors.New("public_ip is required when role is lighthouse or relay")

// ErrRoleRequiresListenPort is the listen_port counterpart of
// ErrRoleRequiresPublicIP: peers compose static_host_map entries as
// "public_ip:listen_port", so a zero port produces the same silent failure.
var ErrRoleRequiresListenPort = errors.New("listen_port is required when role is lighthouse or relay")

// ValidateRoleReachability rejects role/reachability combinations that
// would result in a silently-useless host. role=lighthouse and role=relay
// must both ship with a routable public_ip and a non-zero listen_port —
// otherwise peer config.yml renders an empty static_host_map and the host
// is never dialed (issue #94).
func ValidateRoleReachability(role HostRole, publicIP string, listenPort int) error {
	if !role.Lighthouse() && !role.Relay() {
		return nil
	}
	if strings.TrimSpace(publicIP) == "" {
		return ErrRoleRequiresPublicIP
	}
	if listenPort == 0 {
		return ErrRoleRequiresListenPort
	}
	return nil
}

type Host struct {
	ID                  string        `json:"id"`
	NetworkID           string        `json:"network_id"`
	CAID                string        `json:"ca_id,omitempty"`
	Name                string        `json:"name"`
	NebulaIPs           []string      `json:"nebula_ips"`
	Groups              []string      `json:"groups"`
	Role                HostRole      `json:"role"`
	IsLighthouse        bool          `json:"is_lighthouse"`
	IsRelay             bool          `json:"is_relay"`
	PublicIP            string        `json:"public_ip,omitempty"`
	ListenPort          int           `json:"listen_port,omitempty"`
	Status              HostStatus    `json:"status"`
	CertFingerprint     string        `json:"cert_fingerprint,omitempty"`
	PrevCertFingerprint string        `json:"prev_cert_fingerprint,omitempty"`
	CertExpiresAt       *time.Time    `json:"cert_expires_at,omitempty"`
	CertRotatedAt       *time.Time    `json:"cert_rotated_at,omitempty"`
	PendingRekey        bool          `json:"pending_rekey,omitempty"`
	SigningPubPEM       string        `json:"signing_pub_pem,omitempty"`
	LastSeenAt          *time.Time    `json:"last_seen_at,omitempty"`
	Advanced            *HostAdvanced `json:"advanced,omitempty"`
	Kind                HostKind      `json:"kind"`
	Variant             HostVariant   `json:"variant,omitempty"`
	CreatedAt           time.Time     `json:"created_at"`
	UpdatedAt           time.Time     `json:"updated_at"`
}

// MaxAddressesPerHost is the maximum number of overlay addresses a host can have.
// This is a soft limit to prevent cert bloat; Nebula v2 certs have no hard limit
// but practical deployments should not exceed this without good reason.
const MaxAddressesPerHost = 16

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
