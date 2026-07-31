package meshimport

import (
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

type AgentProfile = models.AgentProfile

type FirewallRule struct {
	Port      string `json:"port"`
	Proto     string `json:"proto"`
	Group     string `json:"group"`
	Cidr      string `json:"cidr,omitempty"`
	LocalCidr string `json:"local_cidr,omitempty"`
}

type FirewallPolicy struct {
	Inbound  []FirewallRule `json:"inbound"`
	Outbound []FirewallRule `json:"outbound"`
}

type UnsafeRoute struct {
	Route string `json:"route"`
	Via   string `json:"via"`
}

type ConfigSnapshot struct {
	ReportedName       string              `json:"reported_name,omitempty"`
	CARootFingerprints []string            `json:"ca_root_fingerprints,omitempty"`
	Blocklist          []string            `json:"blocklist,omitempty"`
	StaticHostMap      map[string][]string `json:"static_host_map,omitempty"`
	LighthouseHosts    []string            `json:"lighthouse_hosts,omitempty"`
	Relays             []string            `json:"relays,omitempty"`
	AmLighthouse       bool                `json:"am_lighthouse,omitempty"`
	AmRelay            bool                `json:"am_relay,omitempty"`
	ListenHost         string              `json:"listen_host,omitempty"`
	ListenPort         int                 `json:"listen_port,omitempty"`
	Punchy             *bool               `json:"punchy,omitempty"`
	MTU                int                 `json:"mtu,omitempty"`
	TunDevice          string              `json:"tun_device,omitempty"`
	UnsafeRoutes       []UnsafeRoute       `json:"unsafe_routes,omitempty"`
	Firewall           FirewallPolicy      `json:"firewall"`
	UnsupportedKeys    []string            `json:"unsupported_keys,omitempty"`
}

type Snapshot struct {
	ID             string         `json:"id"`
	HostID         string         `json:"host_id"`
	CertificatePEM string         `json:"certificate_pem"`
	Profile        AgentProfile   `json:"profile"`
	Config         ConfigSnapshot `json:"config"`
}

type ReconcileInput struct {
	NetworkID        string
	CAID             string
	NetworkCIDRs     []string
	CACertificatePEM string
	CAFingerprint    string
	Snapshots        []Snapshot
	Now              time.Time
	NearExpiryWindow time.Duration
	ValidationLimits Limits
}

type Issue struct {
	Code       string `json:"code"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	HostName   string `json:"host_name,omitempty"`
	Field      string `json:"field,omitempty"`
	Message    string `json:"message"`
}

type HostProposal struct {
	SnapshotID string       `json:"snapshot_id"`
	Profile    AgentProfile `json:"profile"`
	Host       models.Host  `json:"host"`
}

type Proposal struct {
	Hosts     []HostProposal `json:"hosts"`
	Firewall  FirewallPolicy `json:"firewall"`
	Blocklist []string       `json:"blocklist"`
}

type Report struct {
	Blockers []Issue  `json:"blockers"`
	Warnings []Issue  `json:"warnings"`
	Proposal Proposal `json:"proposal"`
}

const (
	IssueInvalidSnapshot            = "invalid_snapshot"
	IssueInvalidCA                  = "invalid_ca"
	IssueCAFingerprintMismatch      = "ca_fingerprint_mismatch"
	IssueCACertificateExpired       = "ca_certificate_expired"
	IssueCACertificateNearExpiry    = "ca_certificate_near_expiry"
	IssueInvalidHostCertificate     = "invalid_host_certificate"
	IssueInvalidHostAddresses       = "invalid_host_addresses"
	IssueInvalidUnsafeNetworks      = "invalid_unsafe_networks"
	IssueHostCertificateExpired     = "host_certificate_expired"
	IssueHostCertificateNotYetValid = "host_certificate_not_yet_valid"
	IssueHostCertificateNearExpiry  = "host_certificate_near_expiry"
	IssueConfigNameMismatch         = "config_name_mismatch"
	IssueAddressOutsideNetwork      = "address_outside_network"
	IssueDuplicateOverlayAddress    = "duplicate_overlay_address"
	IssueEndpointConflict           = "endpoint_conflict"
	IssueInvalidEndpoint            = "invalid_endpoint"
	IssueUnknownStaticHost          = "unknown_static_host"
	IssueUnresolvedLighthouse       = "unresolved_lighthouse"
	IssueUnresolvedRelay            = "unresolved_relay"
	IssueMissingRoleEndpoint        = "missing_role_endpoint"
	IssueDivergentFirewall          = "divergent_firewall"
	IssueInvalidFirewall            = "invalid_firewall"
	IssueInvalidAdvanced            = "invalid_advanced"
	IssueDivergentBlocklist         = "divergent_blocklist"
	IssueInvalidBlocklist           = "invalid_blocklist"
	IssueExtraCARoot                = "extra_ca_root"
	IssueUnsupportedConfigKey       = "unsupported_config_key"
	IssueInvalidNetworkCIDR         = "invalid_network_cidr"
)
