package store

import (
	"context"
	"time"

	"github.com/juev/nebula-mgmt/internal/models"
)

// HostFilter specifies filters for listing hosts.
type HostFilter struct {
	NetworkID string
	Group     string
	Status    models.HostStatus
	Limit     int // 0 = no limit
}

// AuditFilter specifies filters for audit log queries.
type AuditFilter struct {
	Action string
	Limit  int
}

// Store defines the persistence interface for the management server.
type Store interface {
	// Networks
	CreateNetwork(ctx context.Context, n *models.Network) error
	GetNetwork(ctx context.Context, id string) (*models.Network, error)
	ListNetworks(ctx context.Context) ([]*models.Network, error)

	// Hosts
	CreateHost(ctx context.Context, h *models.Host) error
	GetHost(ctx context.Context, id string) (*models.Host, error)
	GetHostByFingerprint(ctx context.Context, fingerprint string) (*models.Host, error)
	ListHosts(ctx context.Context, filter HostFilter) ([]*models.Host, error)
	UpdateHost(ctx context.Context, h *models.Host) error
	UpdateHostLastSeen(ctx context.Context, id string, t time.Time) error
	UpdateHostCert(ctx context.Context, id, fingerprint string, expiresAt time.Time) error
	UpdateHostStatus(ctx context.Context, id string, status models.HostStatus) error
	DeleteHost(ctx context.Context, id string) error
	BlockHostAndAddToBlocklist(ctx context.Context, id, reason string) (*models.Host, error)
	DeleteHostAndBlockCert(ctx context.Context, id, reason string) error

	// Enrollment tokens
	CreateHostAndToken(ctx context.Context, h *models.Host, t *models.EnrollmentToken) error
	CreateToken(ctx context.Context, t *models.EnrollmentToken) error
	ConsumeToken(ctx context.Context, token string) (*models.EnrollmentToken, error)

	// Certificates
	SaveCertificate(ctx context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error
	SaveCertificateAndEnrollHost(ctx context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error
	SaveCertificateAndUpdateHostCert(ctx context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error
	GetCurrentCertificate(ctx context.Context, hostID string) ([]byte, error)
	GetCertificateInfo(ctx context.Context, hostID string) (*models.CertificateInfo, error)
	ListEnrolledHostCerts(ctx context.Context) ([]*models.CertificateInfo, error)

	// Blocklist
	AddToBlocklist(ctx context.Context, fingerprint, hostID, reason string) error
	RemoveFromBlocklist(ctx context.Context, fingerprint string) error
	GetBlocklist(ctx context.Context) ([]string, error)

	// Config versioning
	BumpNetworkConfigVersion(ctx context.Context, networkID string) error
	GetNetworkConfigVersion(ctx context.Context, networkID string) (int, error)

	// Network config (key-value)
	GetNetworkConfig(ctx context.Context, networkID, key string) (string, error)
	SetNetworkConfig(ctx context.Context, networkID, key, value string) error
	SetNetworkConfigAndBumpVersion(ctx context.Context, networkID, key, value string) error

	// Audit log
	AddAuditEntry(ctx context.Context, actor, action, resource, details string) error
	ListAuditEntries(ctx context.Context, filter AuditFilter) ([]*models.AuditEntry, error)

	// Lifecycle
	Migrate(ctx context.Context) error
	Close() error
}
