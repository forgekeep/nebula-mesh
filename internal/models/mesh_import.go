package models

import (
	"fmt"
	"path"
	"strings"
	"time"
)

const maxAgentProfilePathBytes = 4096

type AgentProfile struct {
	NebulaConfigPath string `json:"nebula_config_path"`
	NebulaCAPath     string `json:"nebula_ca_path"`
	NebulaCertPath   string `json:"nebula_cert_path"`
	NebulaKeyPath    string `json:"nebula_key_path"`
	ConfigAckV1      bool   `json:"config_ack_v1"`
}

func DefaultAgentProfile() AgentProfile {
	return AgentProfile{
		NebulaConfigPath: "/etc/nebula/config.yml",
		NebulaCAPath:     "/etc/nebula/ca.crt",
		NebulaCertPath:   "/etc/nebula/host.crt",
		NebulaKeyPath:    "/etc/nebula/host.key",
	}
}

func (p AgentProfile) Validate() error {
	paths := []struct{ name, value string }{
		{"nebula_config_path", p.NebulaConfigPath},
		{"nebula_ca_path", p.NebulaCAPath},
		{"nebula_cert_path", p.NebulaCertPath},
		{"nebula_key_path", p.NebulaKeyPath},
	}
	seen := make(map[string]string, len(paths))
	for _, item := range paths {
		if item.value == "" || len(item.value) > maxAgentProfilePathBytes || strings.ContainsRune(item.value, '\x00') ||
			!isCleanAbsoluteAgentPath(item.value) {
			return fmt.Errorf("invalid agent profile: %s must be a clean absolute path", item.name)
		}
		key := agentPathKey(item.value)
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("invalid agent profile: %s and %s must differ", previous, item.name)
		}
		seen[key] = item.name
	}
	return nil
}

// isCleanAbsoluteAgentPath reports whether value is an absolute, already-clean
// path in either POSIX or Windows form.
//
// path/filepath is deliberately NOT used here. It compiles to the *server's*
// GOOS, while these paths describe the *agent's* filesystem — so a Windows
// agent enrolling against a Linux server was rejected with "invalid agent
// profile" for C:\ProgramData\Nebula\config.yml, which filepath.IsAbs on Linux
// cannot recognize. The mirror case fails the same way, which is why the
// package's own DefaultAgentProfile did not validate on a Windows host.
//
// The rules are the familiar ones: rooted, canonical, no "." or ".." segments,
// no repeated or trailing separator, and — since Windows treats several
// spellings as one file — a single spelling per path. See agentPathKey for the
// case rule that goes with them.
func isCleanAbsoluteAgentPath(value string) bool {
	if strings.HasPrefix(value, "/") {
		// path.Clean is the POSIX cleaner and is GOOS-independent, unlike
		// filepath.Clean. A bare root names a directory, never one of the
		// four files the profile points at.
		return value != "/" && path.Clean(value) == value
	}
	return isCleanAbsoluteWindowsPath(value)
}

// agentPathKey is the identity a path is compared under by the "these four must
// differ" rule. A POSIX filesystem distinguishes case, so a POSIX path is its
// own key. Windows resolves names case-insensitively, so C:\Nebula\ca.crt and
// c:\nebula\CA.CRT name one file and must collide here.
//
// Case folding is only ever allowed to merge two spellings, never to split
// one, so the worst a locale-specific mapping can do is reject a profile that
// would have been accepted — the safe direction for a rule whose whole job is
// to stop two of these paths naming the same file.
func agentPathKey(value string) string {
	if strings.HasPrefix(value, "/") {
		return value
	}
	return strings.ToLower(value)
}

// isCleanAbsoluteWindowsPath accepts a drive-rooted path (C:\dir\file) or a UNC
// share path (\\server\share\file).
func isCleanAbsoluteWindowsPath(value string) bool {
	// Windows accepts forward slashes too, but allowing both spellings would
	// let one file be stored under two different paths — and the profile's
	// "these four must differ" rule compares text, not inodes.
	if strings.ContainsRune(value, '/') {
		return false
	}
	// \\?\ and \\.\ reach the same files through the Win32 device namespace,
	// which would give every path a second spelling the distinctness rule
	// cannot see through. \\?\ additionally switches off the normalization the
	// segment rules below rely on.
	if strings.HasPrefix(value, `\\?\`) || strings.HasPrefix(value, `\\.\`) {
		return false
	}

	var rest string
	switch {
	case len(value) >= 3 && isASCIILetter(value[0]) && value[1] == ':' && value[2] == '\\':
		rest = value[3:]
	case strings.HasPrefix(value, `\\`):
		// The shortest valid UNC root is \\server\share.
		parts := strings.Split(value[2:], `\`)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return false
		}
		rest = strings.Join(parts[2:], `\`)
	default:
		return false
	}

	if rest == "" {
		return false
	}
	for _, segment := range strings.Split(rest, `\`) {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		// Win32 strips trailing dots and spaces from a component before it
		// reaches the filesystem, so "config.yml." and "config.yml " open the
		// same file as "config.yml" — three spellings of one path, which the
		// distinctness rule would read as three different files.
		if strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ") {
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func (p AgentProfile) IsZero() bool {
	return p.NebulaConfigPath == "" && p.NebulaCAPath == "" && p.NebulaCertPath == "" && p.NebulaKeyPath == "" && !p.ConfigAckV1
}

func (p AgentProfile) WithDefaults() (AgentProfile, error) {
	if p.IsZero() {
		p = DefaultAgentProfile()
	}
	if err := p.Validate(); err != nil {
		return AgentProfile{}, err
	}
	return p, nil
}

type MeshImportStatus string

const (
	MeshImportStatusCollecting MeshImportStatus = "collecting"
	MeshImportStatusFinalized  MeshImportStatus = "finalized"
	MeshImportStatusCanceled   MeshImportStatus = "canceled"
)

func ValidMeshImportStatus(status MeshImportStatus) bool {
	switch status {
	case MeshImportStatusCollecting, MeshImportStatusFinalized, MeshImportStatusCanceled:
		return true
	default:
		return false
	}
}

type MeshImport struct {
	ID                           string           `json:"id"`
	NetworkID                    string           `json:"network_id"`
	CAID                         string           `json:"ca_id"`
	OwnerOperatorID              string           `json:"owner_operator_id"`
	CAFingerprint                string           `json:"ca_fingerprint"`
	Status                       MeshImportStatus `json:"status"`
	ExpectedHosts                *int             `json:"expected_hosts,omitempty"`
	Revision                     int64            `json:"revision"`
	TokenHash                    string           `json:"-"`
	TokenExpiresAt               time.Time        `json:"token_expires_at"`
	CapturedNetworkConfigVersion int              `json:"captured_network_config_version"`
	TerminalReason               string           `json:"terminal_reason,omitempty"`
	CreatedAt                    time.Time        `json:"created_at"`
	UpdatedAt                    time.Time        `json:"updated_at"`
	FinalizedAt                  *time.Time       `json:"finalized_at,omitempty"`
	CanceledAt                   *time.Time       `json:"canceled_at,omitempty"`
}

type MeshImportSnapshot struct {
	ID                     string    `json:"id"`
	MeshImportID           string    `json:"mesh_import_id"`
	HostID                 string    `json:"host_id"`
	CertificateFingerprint string    `json:"certificate_fingerprint"`
	CertificatePEM         string    `json:"certificate_pem"`
	AgentSigningPubPEM     string    `json:"agent_signing_pub_pem"`
	PayloadHash            string    `json:"payload_hash"`
	SnapshotJSON           string    `json:"snapshot_json"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type HostAgentProfile struct {
	HostID               string    `json:"host_id"`
	MeshImportID         string    `json:"mesh_import_id"`
	NebulaConfigPath     string    `json:"nebula_config_path"`
	NebulaCAPath         string    `json:"nebula_ca_path"`
	NebulaCertPath       string    `json:"nebula_cert_path"`
	NebulaKeyPath        string    `json:"nebula_key_path"`
	ConfigAckV1          bool      `json:"config_ack_v1"`
	PendingConfigVersion int       `json:"pending_config_version"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

func (p HostAgentProfile) AgentProfile() AgentProfile {
	return AgentProfile{
		NebulaConfigPath: p.NebulaConfigPath,
		NebulaCAPath:     p.NebulaCAPath,
		NebulaCertPath:   p.NebulaCertPath,
		NebulaKeyPath:    p.NebulaKeyPath,
		ConfigAckV1:      p.ConfigAckV1,
	}
}

type MeshImportChallenge struct {
	ID                     string     `json:"id"`
	MeshImportID           string     `json:"mesh_import_id"`
	TokenHash              string     `json:"-"`
	CertificateFingerprint string     `json:"certificate_fingerprint"`
	AgentSigningPubPEM     string     `json:"agent_signing_pub_pem"`
	PayloadHash            string     `json:"payload_hash"`
	ServerNonce            string     `json:"server_nonce"`
	ExpiresAt              time.Time  `json:"expires_at"`
	ConsumedAt             *time.Time `json:"consumed_at,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
}

type MeshImportTombstone struct {
	CertificateFingerprint string    `json:"certificate_fingerprint"`
	FormerHostID           string    `json:"former_host_id"`
	MeshImportID           string    `json:"mesh_import_id"`
	AgentSigningPubPEM     string    `json:"agent_signing_pub_pem"`
	TerminalReason         string    `json:"terminal_reason"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

type MeshImportRegistration struct {
	ChallengeID          string
	CertificateNotBefore time.Time
	CertificateNotAfter  time.Time
	Host                 *Host
	Snapshot             *MeshImportSnapshot
	Profile              *HostAgentProfile
}

type MeshImportRegistrationResult struct {
	Host     *Host
	Snapshot *MeshImportSnapshot
	Created  bool
}
