package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
)

// CAManager holds a loaded CA certificate and its signing key in memory.
type CAManager struct {
	caCert cert.Certificate
	caKey  ed25519.PrivateKey
}

// NewCA creates a new Curve25519 CA with the given name and duration.
func NewCA(name string, duration time.Duration) (*CAManager, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	now := time.Now()
	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      name,
		IsCA:      true,
		NotBefore: now,
		NotAfter:  now.Add(duration),
		PublicKey: pub,
		Curve:     cert.Curve_CURVE25519,
	}

	c, err := tbs.Sign(nil, cert.Curve_CURVE25519, priv)
	if err != nil {
		return nil, fmt.Errorf("sign CA: %w", err)
	}

	return &CAManager{caCert: c, caKey: priv}, nil
}

// LoadCAFromMaterial builds a CAManager from a PEM-encoded CA certificate
// and the raw ed25519 private key. Used by the DB-backed multi-CA path
// where key material is decrypted on demand via the keystore package.
func LoadCAFromMaterial(certPEM []byte, rawKey ed25519.PrivateKey) (*CAManager, error) {
	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	if !c.IsCA() {
		return nil, fmt.Errorf("certificate is not a CA")
	}
	if len(rawKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("raw key length: %d, want %d", len(rawKey), ed25519.PrivateKeySize)
	}
	// The private key must actually be the one the cert certifies — a
	// mismatch means the DB row pairs this cert with a foreign key (e.g. a
	// pre-AAD envelope swapped between CA rows) and every cert signed with
	// it would fail peer validation. Refuse at load instead of minting
	// unusable certificates.
	if pub, ok := rawKey.Public().(ed25519.PublicKey); !ok || !pub.Equal(ed25519.PublicKey(c.PublicKey())) {
		return nil, fmt.Errorf("CA private key does not match certificate public key")
	}
	return &CAManager{caCert: c, caKey: rawKey}, nil
}

// RawKey returns the in-memory ed25519 private key. Used by the migration
// path to re-encrypt a legacy file-based CA under the master key. Treat
// the returned slice as sensitive and zeroise once done.
func (m *CAManager) RawKey() ed25519.PrivateKey {
	return m.caKey
}

// Wipe overwrites the in-memory plaintext signing key with zeros so it
// no longer lingers on the Go heap waiting for GC. Callers MUST defer
// this immediately after LoadByID / NewCA, per the keystore package's
// "zeroise the plaintext as soon as it is no longer needed" contract.
// After Wipe(), any subsequent Sign() will produce invalid signatures.
// Closes GHSA-8h84-fhqq-q58v.
//
// Nil-safe so `defer caMgr.Wipe()` placed before the error check is
// also safe — load failures return nil and the defer becomes a no-op.
func (m *CAManager) Wipe() {
	if m == nil {
		return
	}
	keystore.Zeroize(m.caKey)
}

// CACert returns the CA certificate.
func (m *CAManager) CACert() cert.Certificate {
	return m.caCert
}

// CACertPEM returns the PEM-encoded CA certificate.
func (m *CAManager) CACertPEM() ([]byte, error) {
	return m.caCert.MarshalPEM()
}

// CACertFingerprint returns the SHA256 fingerprint of the CA certificate.
func (m *CAManager) CACertFingerprint() (string, error) {
	return m.caCert.Fingerprint()
}
