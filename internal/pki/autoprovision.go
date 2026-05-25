package pki

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

// MintStore is the narrow interface for store operations needed by MintAndStoreCA.
// It isolates pki from a concrete dependency on store.Store, enabling better testing
// and layering.
type MintStore interface {
	// CreateCA persists a new CA record to the store.
	CreateCA(ctx context.Context, c *models.CA) error
	// ListCAsByOwner returns all CAs owned by the given operator.
	ListCAsByOwner(ctx context.Context, ownerID string) ([]*models.CA, error)
	// AddAuditEntry records an action in the audit log (best-effort).
	AddAuditEntry(ctx context.Context, actor, action, resource, details string) error
}

// MintRequest describes parameters for MintAndStoreCA.
type MintRequest struct {
	// Operator is the owner of the CA to be minted.
	Operator *models.Operator
	// Name is the user-facing name for the CA (e.g. "alice-default").
	Name string
	// Duration is the validity period for the cert (e.g. 10 * 365 * 24 * time.Hour).
	Duration time.Duration
	// SkipIfActive, when true, causes the function to return an existing active CA
	// for the operator instead of minting a new one (idempotent behavior).
	SkipIfActive bool
}

var ErrMasterRequired = errors.New("master keystore is required")

// MintAndStoreCA creates a new CA for the given operator and persists it to the store.
// If SkipIfActive is set and the operator already has an active CA, the existing one is
// returned with minted=false. Returns (ca, true, nil) on successful creation,
// (existing, false, nil) if skipped due to existing CA, or (nil, false, err) on failure.
func MintAndStoreCA(ctx context.Context, s MintStore, master *keystore.Master, logger *slog.Logger, req MintRequest) (*models.CA, bool, error) {
	if master == nil {
		return nil, false, ErrMasterRequired
	}
	if req.Operator == nil {
		return nil, false, fmt.Errorf("operator is required")
	}
	if req.Name == "" {
		return nil, false, fmt.Errorf("CA name is required")
	}

	// Idempotence: if SkipIfActive is set, check for an existing active CA.
	if req.SkipIfActive {
		existing, err := s.ListCAsByOwner(ctx, req.Operator.ID)
		if err != nil {
			return nil, false, fmt.Errorf("list existing CAs: %w", err)
		}
		for _, ca := range existing {
			if ca.Status == models.CAStatusActive {
				return ca, false, nil
			}
		}
	}

	// Mint a new CA.
	mgr, err := NewCA(req.Name, req.Duration)
	if err != nil {
		return nil, false, fmt.Errorf("create CA: %w", err)
	}

	// Extract and encrypt the private key.
	rawKey := mgr.RawKey()
	defer keystore.Zeroize(rawKey)

	dek, wrappedDEK, err := master.GenerateDEK()
	if err != nil {
		return nil, false, fmt.Errorf("generate DEK: %w", err)
	}
	defer keystore.Zeroize(dek)

	wrappedKey, err := keystore.SealWithDEK(dek, rawKey)
	if err != nil {
		return nil, false, fmt.Errorf("seal key: %w", err)
	}

	// Extract cert metadata.
	certPEM, err := mgr.CACertPEM()
	if err != nil {
		return nil, false, fmt.Errorf("marshal CA cert: %w", err)
	}

	fp, err := mgr.CACertFingerprint()
	if err != nil {
		return nil, false, fmt.Errorf("fingerprint: %w", err)
	}

	notBefore := mgr.CACert().NotBefore()
	notAfter := mgr.CACert().NotAfter()

	// Construct the CA model and persist.
	now := time.Now()
	ca := &models.CA{
		ID:                   uuid.New().String(),
		Name:                 req.Name,
		OwnerOperatorID:      req.Operator.ID,
		CertPEM:              string(certPEM),
		Fingerprint:          fp,
		NotBefore:            notBefore,
		NotAfter:             notAfter,
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      wrappedDEK.Ciphertext,
		NonceDEK:             wrappedDEK.Nonce,
		EncryptedKeyMaterial: wrappedKey.Ciphertext,
		NonceKey:             wrappedKey.Nonce,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	if err := s.CreateCA(ctx, ca); err != nil {
		return nil, false, fmt.Errorf("store CA: %w", err)
	}

	// Record audit entry (best-effort).
	_ = s.AddAuditEntry(ctx, req.Operator.Username, "ca.created", ca.ID, fmt.Sprintf("name=%s fp=%s", ca.Name, ca.Fingerprint))

	if logger != nil {
		logger.Info("CA minted and stored",
			"ca_id", ca.ID,
			"name", ca.Name,
			"operator", req.Operator.Username,
			"fingerprint", fp)
	}

	return ca, true, nil
}
