package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

// DefaultCAName is the name assigned to the imported legacy CA when the
// `cas` table is initially populated.
const DefaultCAName = "default"

// ImportLegacyCAIfNeeded checks whether the cas table is empty and, if so,
// reads the legacy CA cert/key pair from data_dir/{ca.crt,ca.key}, decrypts
// it with the legacy passphrase, re-wraps the raw key under the supplied
// master keystore and persists the new "default" CA row. The returned ID is
// the inserted CA's id (or the existing default CA's id if one was already
// present).
//
// adminID is the operator id used as owner. The function is a no-op when
// adminID is empty.
//
// On success the original ca.{crt,key} files are left in place for one
// release (per ADR 0002 §4.5) so operators can roll back without losing
// signing material.
func ImportLegacyCAIfNeeded(
	ctx context.Context,
	s store.Store,
	master *keystore.Master,
	certPath, keyPath, passphrase, adminID string,
) (string, bool, error) {
	if master == nil {
		return "", false, fmt.Errorf("master keystore is nil")
	}

	cas, err := s.ListCAs(ctx)
	if err != nil {
		return "", false, fmt.Errorf("list CAs: %w", err)
	}
	if len(cas) > 0 {
		for _, c := range cas {
			if c.Name == DefaultCAName {
				return c.ID, false, nil
			}
		}
		// At least one CA exists but none is named "default"; treat the
		// first as the implicit default.
		return cas[0].ID, false, nil
	}

	if adminID == "" {
		return "", false, nil
	}

	if _, err := os.Stat(certPath); err != nil {
		return "", false, nil // nothing to import
	}
	if _, err := os.Stat(keyPath); err != nil {
		return "", false, nil
	}

	mgr, err := pki.LoadCA(certPath, keyPath, passphrase)
	if err != nil {
		return "", false, fmt.Errorf("load legacy CA: %w", err)
	}

	certPEM, err := mgr.CACertPEM()
	if err != nil {
		return "", false, fmt.Errorf("marshal CA cert: %w", err)
	}
	fp, err := mgr.CACertFingerprint()
	if err != nil {
		return "", false, fmt.Errorf("fingerprint: %w", err)
	}
	rawKey := mgr.RawKey()
	defer keystore.Zeroize(rawKey)

	dek, wrappedDEK, err := master.GenerateDEK()
	if err != nil {
		return "", false, err
	}
	defer keystore.Zeroize(dek)
	wrappedKey, err := keystore.SealWithDEK(dek, rawKey)
	if err != nil {
		return "", false, err
	}

	notBefore := mgr.CACert().NotBefore()
	notAfter := mgr.CACert().NotAfter()
	now := time.Now()
	c := &models.CA{
		ID:                   uuid.New().String(),
		Name:                 DefaultCAName,
		OwnerOperatorID:      adminID,
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
	if err := s.CreateCA(ctx, c); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", false, err
		}
		return "", false, fmt.Errorf("insert legacy CA: %w", err)
	}

	// Backfill ca_id on existing networks / hosts / certificates / blocklist
	// so the migrated default CA owns the pre-existing data.
	if err := s.BackfillCAID(ctx, c.ID); err != nil {
		fmt.Fprintf(os.Stderr, "backfill ca_id: %v\n", err)
	}

	return c.ID, true, nil
}
