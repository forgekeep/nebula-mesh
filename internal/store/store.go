package store

import (
	"context"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
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
	// CAs
	CreateCA(ctx context.Context, c *models.CA) error
	GetCA(ctx context.Context, id string) (*models.CA, error)
	GetCAByFingerprint(ctx context.Context, fp string) (*models.CA, error)
	ListCAs(ctx context.Context) ([]*models.CA, error)
	ListCAsByOwner(ctx context.Context, ownerID string) ([]*models.CA, error)
	ListCAsApproachingExpiry(ctx context.Context, thresholdRatio float64) ([]*models.CA, error)
	FindCAByPredecessor(ctx context.Context, predecessorID string) (*models.CA, error)
	UpdateCAStatus(ctx context.Context, id string, status models.CAStatus) error
	DeleteCA(ctx context.Context, id string) error

	// Networks
	CreateNetwork(ctx context.Context, n *models.Network) error
	GetNetwork(ctx context.Context, id string) (*models.Network, error)
	ListNetworks(ctx context.Context) ([]*models.Network, error)
	UpdateNetwork(ctx context.Context, n *models.Network) error

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
	UnblockHostAndRemoveFromBlocklist(ctx context.Context, id string) (*models.Host, error)
	DeleteHostAndBlockCert(ctx context.Context, id, reason string) error

	// Agent authorization (ADR 0004 / #75).
	//
	// SetPrevFingerprint records the prior cert fingerprint and the time of
	// rotation; SaveCertificateAndUpdateHostCert is the natural caller.
	// ClearPrevFingerprint drops the overlap window once the agent has
	// successfully polled under the new fingerprint.
	//
	// SetPendingRekey is a compare-and-swap that succeeds only when the host
	// is not already mid-rekey; the second concurrent call returns
	// ErrRekeyAlreadyPending so the API layer can answer 409.
	SetPrevFingerprint(ctx context.Context, hostID, prev string, rotatedAt time.Time) error
	ClearPrevFingerprint(ctx context.Context, hostID string) error
	SetPendingRekey(ctx context.Context, hostID string) error
	ClearPendingRekey(ctx context.Context, hostID string) error
	UpdateHostSigningPub(ctx context.Context, hostID, signingPubPEM string) error

	// AddPopNonce records a (hostID, nonce) pair valid until expiresAt.
	// Returns nil when the row was freshly inserted (or replaced an expired
	// duplicate); returns ErrReplayedNonce when a live duplicate exists.
	// Rows past expiresAt are pruned lazily on the next call; callers must
	// not infer freshness from the row's age alone. GHSA-v2jf-442r-6mjh.
	AddPopNonce(ctx context.Context, hostID, nonce string, expiresAt time.Time) error

	// Enrollment tokens
	CreateHostAndToken(ctx context.Context, h *models.Host, t *models.EnrollmentToken) error
	CreateToken(ctx context.Context, t *models.EnrollmentToken) error
	CreateTokenForHost(ctx context.Context, hostID, token string, expiresAt time.Time) error
	ConsumeToken(ctx context.Context, token string) (*models.EnrollmentToken, error)
	GetEnrollmentToken(ctx context.Context, token string) (*models.EnrollmentToken, error)

	// Certificates
	SaveCertificate(ctx context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error
	SaveCertificateAndEnrollHost(ctx context.Context, hostID string, certPEM []byte, fp string, notBefore, notAfter time.Time) error
	ConsumeTokenAndEnrollHost(ctx context.Context, hostID, token string, certPEM []byte, fp string, notBefore, notAfter time.Time) error
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
	GetHostConfigVersion(ctx context.Context, hostID string) (int, error)
	UpdateHostConfigVersion(ctx context.Context, hostID string, version int) error

	// Network config (key-value)
	GetNetworkConfig(ctx context.Context, networkID, key string) (string, error)
	SetNetworkConfig(ctx context.Context, networkID, key, value string) error
	SetNetworkConfigAndBumpVersion(ctx context.Context, networkID, key, value string) error

	// Audit log
	AddAuditEntry(ctx context.Context, actor, action, resource, details string) error
	ListAuditEntries(ctx context.Context, filter AuditFilter) ([]*models.AuditEntry, error)

	// Cert-expiry alert dedup state. RecordCertAlert remembers that an
	// alert was emitted for the given host whose current cert expires at
	// alertedNotAfter; GetCertAlert returns the previously alerted
	// not_after, or ErrNotFound if no alert has been recorded yet.
	RecordCertAlert(ctx context.Context, hostID string, alertedNotAfter time.Time) error
	GetCertAlert(ctx context.Context, hostID string) (time.Time, error)

	// Server-wide key/value settings (e.g. enforce_2fa). Empty string is
	// returned when the key has never been set — callers convert to typed
	// defaults via the helpers in the consuming package.
	GetServerSetting(ctx context.Context, key string) (string, error)
	SetServerSetting(ctx context.Context, key, value string) error

	// Operators
	CreateOperator(ctx context.Context, op *models.Operator) error
	// SeedInitialAdminOperator atomically inserts op (and optionally key,
	// when key is non-nil) only if the operators table is empty. Returns
	// (true, nil) when this call performed the seed, (false, nil) when
	// another caller already populated the table. The check + insert run
	// in a single transaction, so concurrent boots cannot both seed.
	SeedInitialAdminOperator(ctx context.Context, op *models.Operator, key *models.OperatorAPIKey) (bool, error)
	GetOperator(ctx context.Context, id string) (*models.Operator, error)
	GetOperatorByUsername(ctx context.Context, username string) (*models.Operator, error)
	GetOperatorByOIDC(ctx context.Context, issuer, subject string) (*models.Operator, error)
	ListOperators(ctx context.Context) ([]*models.Operator, error)
	UpdateOperatorPassword(ctx context.Context, id, passwordHash string) error
	UpdateOperatorLastLogin(ctx context.Context, id string, t time.Time) error
	DisableOperator(ctx context.Context, id string) error
	EnableOperator(ctx context.Context, id string) error

	// Operator TOTP / recovery codes
	SetOperatorTOTP(ctx context.Context, id, secret string, enabled bool) error
	ReplaceOperatorRecoveryCodes(ctx context.Context, id string, codeHashes []string) error
	ConsumeOperatorRecoveryCode(ctx context.Context, id, codeHash string) error
	ListOperatorRecoveryCodes(ctx context.Context, id string) ([]string, error)

	// Operator API keys
	CreateOperatorAPIKey(ctx context.Context, k *models.OperatorAPIKey) error
	GetOperatorAPIKey(ctx context.Context, keyID string) (*models.OperatorAPIKey, error)
	GetOperatorByAPIKeyHash(ctx context.Context, keyHash string) (*models.Operator, *models.OperatorAPIKey, error)
	ListOperatorAPIKeys(ctx context.Context, operatorID string) ([]*models.OperatorAPIKey, error)
	RevokeOperatorAPIKey(ctx context.Context, keyID string) error
	TouchOperatorAPIKey(ctx context.Context, keyID string, t time.Time) error

	// Operator sessions
	CreateOperatorSession(ctx context.Context, s *models.OperatorSession) error
	GetOperatorBySession(ctx context.Context, token string) (*models.Operator, error)
	GetPendingTwoFactorOperator(ctx context.Context, token string) (*models.Operator, error)
	PromoteOperatorSession(ctx context.Context, token string, newExpiry time.Time) error
	DeleteOperatorSession(ctx context.Context, token string) error
	DeleteOperatorSessionsByOperator(ctx context.Context, operatorID string) error
	DeleteExpiredOperatorSessions(ctx context.Context, before time.Time) error

	// Lifecycle
	Migrate(ctx context.Context) error
	Ping(ctx context.Context) error
	Close() error
}
