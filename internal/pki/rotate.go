package pki

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// RotateAndStoreCA creates a new CA that succeeds the given oldCA and persists it to the store.
// It implements CA rotation: minting a new certificate with the same lifetime as its predecessor,
// and establishing the predecessor link for trust bundle management.
//
// The rotation is idempotent: if an active successor already exists for oldCA, it is returned
// without creating a duplicate. This handles cases where rotation is retried after partial failures.
func RotateAndStoreCA(
	ctx context.Context,
	s store.Store,
	master *keystore.Master,
	logger *slog.Logger,
	oldCA *models.CA,
) (*models.CA, error) {
	// Validation.
	if master == nil {
		return nil, ErrMasterRequired
	}
	if oldCA == nil {
		return nil, fmt.Errorf("oldCA required")
	}
	if oldCA.Status != models.CAStatusActive {
		return nil, fmt.Errorf("cannot rotate non-active CA: status=%s", oldCA.Status)
	}

	// Idempotence: check if an active successor already exists.
	existing, err := s.FindCAByPredecessor(ctx, oldCA.ID)
	if err == nil && existing != nil {
		// Successor already exists and is active.
		return existing, nil
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("check for existing successor: %w", err)
	}

	// Compute new CA duration (same as predecessor).
	duration := oldCA.NotAfter.Sub(oldCA.NotBefore)

	// Generate new name.
	newName := oldCA.Name + "-rotated"

	// Mint a new CA.
	mgr, err := NewCA(newName, duration)
	if err != nil {
		return nil, fmt.Errorf("create CA: %w", err)
	}

	// Extract and encrypt the private key.
	rawKey := mgr.RawKey()
	defer keystore.Zeroize(rawKey)

	dek, wrappedDEK, err := master.GenerateDEK()
	if err != nil {
		return nil, fmt.Errorf("generate DEK: %w", err)
	}
	defer keystore.Zeroize(dek)

	wrappedKey, err := keystore.SealWithDEK(dek, rawKey)
	if err != nil {
		return nil, fmt.Errorf("seal key: %w", err)
	}

	// Extract cert metadata.
	certPEM, err := mgr.CACertPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal CA cert: %w", err)
	}

	fp, err := mgr.CACertFingerprint()
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}

	notBefore := mgr.CACert().NotBefore()
	notAfter := mgr.CACert().NotAfter()

	// Construct the new CA model and persist.
	now := time.Now()
	newCA := &models.CA{
		ID:                   uuid.New().String(),
		Name:                 newName,
		OwnerOperatorID:      oldCA.OwnerOperatorID,
		CertPEM:              string(certPEM),
		Fingerprint:          fp,
		NotBefore:            notBefore,
		NotAfter:             notAfter,
		Status:               models.CAStatusActive,
		PredecessorID:        &oldCA.ID,
		EncryptedKeyDEK:      wrappedDEK.Ciphertext,
		NonceDEK:             wrappedDEK.Nonce,
		EncryptedKeyMaterial: wrappedKey.Ciphertext,
		NonceKey:             wrappedKey.Nonce,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	if err := s.CreateCA(ctx, newCA); err != nil {
		return nil, fmt.Errorf("store CA: %w", err)
	}

	// Record audit entry (best-effort).
	// Use OwnerOperatorID as actor since operator username is not available in this context.
	_ = s.AddAuditEntry(ctx, oldCA.OwnerOperatorID, "ca.rotated", newCA.ID, fmt.Sprintf("predecessor=%s name=%s fp=%s", oldCA.ID, newCA.Name, fp))

	if logger != nil {
		logger.Info("CA rotated and stored",
			"new_ca_id", newCA.ID,
			"old_ca_id", oldCA.ID,
			"fingerprint", fp)
	}

	return newCA, nil
}
