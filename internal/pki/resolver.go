package pki

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

// CAStore is the subset of the application store interface required by
// CAResolver. Kept narrow so this package can depend only on what it uses.
type CAStore interface {
	GetCA(ctx context.Context, id string) (*models.CA, error)
}

// CAResolver loads CAs from the database, decrypts their private key
// material with the master keystore, and returns a CAManager bound to the
// requested CA. The unwrapped key material lives only inside the returned
// manager; CAResolver does NOT cache anything across calls so a disable /
// rotation takes effect immediately.
type CAResolver struct {
	store  CAStore
	master *keystore.Master
}

// NewCAResolver builds a resolver. The master keystore must be the same
// one used when CAs were created/imported.
func NewCAResolver(store CAStore, master *keystore.Master) *CAResolver {
	return &CAResolver{store: store, master: master}
}

// LoadByID returns a CAManager for the CA identified by caID. The caller
// is responsible for not retaining the manager beyond the signing scope.
func (r *CAResolver) LoadByID(ctx context.Context, caID string) (*CAManager, error) {
	if r == nil {
		return nil, fmt.Errorf("CAResolver is nil")
	}
	if r.master == nil {
		return nil, fmt.Errorf("master keystore not configured")
	}
	c, err := r.store.GetCA(ctx, caID)
	if err != nil {
		return nil, fmt.Errorf("load CA %s: %w", caID, err)
	}
	// Try the ca_id-bound envelope first; fall back to nil AAD for
	// envelopes sealed before the binding existed. The fallback does not
	// reopen the swap it guards against: an AAD-bound envelope copied from
	// another CA's row fails both opens (its tag covers the source CA's
	// ID), and a swapped-in legacy envelope is caught by the public-key
	// consistency check in LoadCAFromMaterial.
	wrappedDEK := keystore.WrappedKey{
		Ciphertext: c.EncryptedKeyDEK,
		Nonce:      c.NonceDEK,
	}
	aad := []byte(caID)
	dek, err := r.master.UnwrapDEK(wrappedDEK, aad)
	if err != nil {
		dek, err = r.master.UnwrapDEK(wrappedDEK, nil)
		if err != nil {
			return nil, fmt.Errorf("unwrap DEK for CA %s: %w", caID, err)
		}
		aad = nil
	}
	defer keystore.Zeroize(dek)

	keyBytes, err := keystore.OpenWithDEK(dek, keystore.WrappedBlob{
		Ciphertext: c.EncryptedKeyMaterial,
		Nonce:      c.NonceKey,
	}, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt CA %s key: %w", caID, err)
	}
	return loadCAOrZeroize([]byte(c.CertPEM), keyBytes)
}

// loadCAOrZeroize builds a CAManager from freshly-decrypted key material,
// transferring ownership of keyBytes to the manager on success (the caller
// later clears it via CAManager.Wipe). If construction fails — e.g. the cert
// is unparseable or not a CA — the plaintext key never reaches a manager, so
// it is zeroized here rather than left on the heap for the GC (#181).
func loadCAOrZeroize(certPEM, keyBytes []byte) (*CAManager, error) {
	mgr, err := LoadCAFromMaterial(certPEM, ed25519.PrivateKey(keyBytes))
	if err != nil {
		keystore.Zeroize(keyBytes)
		return nil, err
	}
	return mgr, nil
}
