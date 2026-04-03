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

type Host struct {
	ID              string     `json:"id"`
	NetworkID       string     `json:"network_id"`
	Name            string     `json:"name"`
	NebulaIP        string     `json:"nebula_ip"`
	Groups          []string   `json:"groups"`
	Role            HostRole   `json:"role"`
	IsLighthouse    bool       `json:"is_lighthouse"`
	IsRelay         bool       `json:"is_relay"`
	PublicIP        string     `json:"public_ip,omitempty"`
	ListenPort      int        `json:"listen_port,omitempty"`
	Status          HostStatus `json:"status"`
	CertFingerprint string     `json:"cert_fingerprint,omitempty"`
	CertExpiresAt   *time.Time `json:"cert_expires_at,omitempty"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}
