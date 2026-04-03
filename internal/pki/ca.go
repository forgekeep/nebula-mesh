package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"time"

	"github.com/slackhq/nebula/cert"
)

const defaultPassphrase = "nebula-mgmt-default"

// CAManager holds a loaded CA certificate and its signing key in memory.
type CAManager struct {
	caCert cert.Certificate
	caKey  ed25519.PrivateKey
}

// NewCA creates a new Curve25519 CA with the given name and duration.
// Returns the manager and the encrypted key PEM (for backup display).
func NewCA(name string, duration time.Duration) (*CAManager, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
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
		return nil, nil, fmt.Errorf("sign CA: %w", err)
	}

	// Encrypt key for backup display
	kdfParams := cert.NewArgon2Parameters(64*1024, 1, 1)
	encKeyPEM, err := cert.EncryptAndMarshalSigningPrivateKey(
		cert.Curve_CURVE25519, priv, []byte(defaultPassphrase), kdfParams,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt CA key: %w", err)
	}

	return &CAManager{caCert: c, caKey: priv}, encKeyPEM, nil
}

// LoadCA loads a CA from certificate and encrypted key PEM files.
func LoadCA(certPath, keyPath, passphrase string) (*CAManager, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}

	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	if !c.IsCA() {
		return nil, fmt.Errorf("certificate is not a CA")
	}

	_, rawKey, _, err := cert.DecryptAndUnmarshalSigningPrivateKey([]byte(passphrase), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("decrypt CA key: %w", err)
	}

	return &CAManager{caCert: c, caKey: rawKey}, nil
}

// Save writes the CA certificate and encrypted key to disk.
func (m *CAManager) Save(certPath, keyPath, passphrase string) error {
	certPEM, err := m.caCert.MarshalPEM()
	if err != nil {
		return fmt.Errorf("marshal cert PEM: %w", err)
	}

	kdfParams := cert.NewArgon2Parameters(64*1024, 1, 1)
	encKeyPEM, err := cert.EncryptAndMarshalSigningPrivateKey(
		cert.Curve_CURVE25519, m.caKey, []byte(passphrase), kdfParams,
	)
	if err != nil {
		return fmt.Errorf("encrypt CA key: %w", err)
	}

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, encKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}

	return nil
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
