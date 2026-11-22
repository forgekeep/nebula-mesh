package pki

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

// CAStore is the subset of the application store interface required by
// CAResolver. Kept narrow so this package can depend only on what it uses.
type CAStore interface {
	GetCA(ctx context.Context, id string) (*models.CA, error)
}

// CAResolver loads CAs from the database, decrypts their private key
// material with the master keystore for one operation. It neither exposes
// decrypted key material nor caches it across calls.
type CAResolver struct {
	store  CAStore
	master *keystore.Master
}

// NewCAResolver builds a resolver. The master keystore must be the same
// one used when CAs were created/imported.
func NewCAResolver(store CAStore, master *keystore.Master) *CAResolver {
	return &CAResolver{store: store, master: master}
}

// SignHost signs a host certificate and returns it with the public issuer PEM
// from the same CA snapshot. No decrypted manager crosses the PKI boundary.
func (r *CAResolver) SignHost(ctx context.Context, caID string, req SignRequest) (cert.Certificate, []byte, error) {
	return signWithCA(r.loadByID(ctx, caID), req)
}

type loadedCA struct {
	manager *CAManager
	err     error
}

func signWithCA(loaded loadedCA, req SignRequest) (cert.Certificate, []byte, error) {
	defer loaded.manager.Wipe()
	if loaded.err != nil {
		return nil, nil, fmt.Errorf("resolve CA: %w", loaded.err)
	}
	c, err := loaded.manager.Sign(req)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}
	pem, err := loaded.manager.CACertPEM()
	if err != nil {
		return nil, nil, fmt.Errorf("marshal issuer certificate: %w", err)
	}
	return c, pem, nil
}

// VerifyCAKey verifies that the persisted CA's key decrypts and matches its
// certificate, then clears the owned plaintext before returning.
func (r *CAResolver) VerifyCAKey(ctx context.Context, caID string) error {
	return verifyLoadedCA(r.loadByID(ctx, caID))
}

func verifyLoadedCA(loaded loadedCA) error {
	defer loaded.manager.Wipe()
	return loaded.err
}

func (r *CAResolver) loadByID(ctx context.Context, caID string) loadedCA {
	manager, err := r.openCA(ctx, caID)
	return loadedCA{manager: manager, err: err}
}

func (r *CAResolver) openCA(ctx context.Context, caID string) (*CAManager, error) {
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
