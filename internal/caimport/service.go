// Package caimport validates and persists an existing Nebula certificate
// authority without ever storing its plaintext signing key.
package caimport

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

const (
	defaultMaxCertificateBytes = 1 << 20
	defaultMaxPrivateKeyBytes  = 1 << 20
	defaultMaxArgon2MemoryKiB  = 256 * 1024
	defaultMaxArgon2Iterations = 4
	defaultMaxArgon2Parallel   = 4
)

var (
	ErrInvalidMaterial      = errors.New("invalid CA material")
	ErrUnsupportedCurve     = errors.New("unsupported CA curve")
	ErrInvalidValidity      = errors.New("CA certificate is not currently valid")
	ErrKeyMismatch          = errors.New("CA private key does not match certificate")
	ErrDuplicateCA          = errors.New("CA already imported")
	ErrKDFLimits            = errors.New("private key KDF exceeds import limits")
	ErrDecryptBusy          = errors.New("another private key decrypt is in progress")
	ErrMasterKeyUnavailable = errors.New("master keystore not configured")
	ErrInputTooLarge        = errors.New("CA import input is too large")
)

// Limits bounds uploaded material and the work accepted from an encrypted
// Nebula signing key. A zero-valued field is replaced with its safe default.
type Limits struct {
	MaxCertificateBytes  int
	MaxPrivateKeyBytes   int
	MaxArgon2MemoryKiB   uint32
	MaxArgon2Iterations  uint32
	MaxArgon2Parallelism uint8
}

// DefaultLimits returns the production CA import limits.
func DefaultLimits() Limits {
	return Limits{
		MaxCertificateBytes:  defaultMaxCertificateBytes,
		MaxPrivateKeyBytes:   defaultMaxPrivateKeyBytes,
		MaxArgon2MemoryKiB:   defaultMaxArgon2MemoryKiB,
		MaxArgon2Iterations:  defaultMaxArgon2Iterations,
		MaxArgon2Parallelism: defaultMaxArgon2Parallel,
	}
}

// Request contains one existing CA certificate and its signing key. Import
// consumes and zeroizes PrivateKeyPEM and Passphrase before returning.
type Request struct {
	Name            string
	OwnerOperatorID string
	CertificatePEM  []byte
	PrivateKeyPEM   []byte
	Passphrase      []byte
}

type caStore interface {
	CreateCA(ctx context.Context, ca *models.CA) error
	GetCAByFingerprint(ctx context.Context, fingerprint string) (*models.CA, error)
}

// Importer is the shared CA import contract consumed by API and Web. A single
// Service instance should be shared by all server entrypoints so its Argon2
// decrypt slot is process-wide.
type Importer interface {
	Import(ctx context.Context, request Request) (*models.CA, error)
}

// Service implements the shared CA import path used by HTTP and CLI callers.
type Service struct {
	store        caStore
	master       *keystore.Master
	limits       Limits
	decryptSlots chan struct{}
	now          func() time.Time
}

// NewService creates a CA import service. Encrypted key decryption is globally
// serialized per service instance to bound Argon2 memory use.
func NewService(caStore caStore, master *keystore.Master, limits Limits) *Service {
	return &Service{
		store:        caStore,
		master:       master,
		limits:       normalizeLimits(limits),
		decryptSlots: make(chan struct{}, 1),
		now:          time.Now,
	}
}

// Import validates an existing Nebula CA, proves possession of its signing
// key, envelope-encrypts that key, and persists the resulting active CA.
func (s *Service) Import(ctx context.Context, request Request) (*models.CA, error) {
	defer keystore.Zeroize(request.PrivateKeyPEM)
	defer keystore.Zeroize(request.Passphrase)

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || s.master == nil {
		return nil, ErrMasterKeyUnavailable
	}
	if s.store == nil {
		return nil, fmt.Errorf("%w: CA store not configured", ErrInvalidMaterial)
	}
	name := strings.TrimSpace(request.Name)
	ownerID := strings.TrimSpace(request.OwnerOperatorID)
	if name == "" || ownerID == "" || len(request.CertificatePEM) == 0 || len(request.PrivateKeyPEM) == 0 {
		return nil, fmt.Errorf("%w: name, owner, certificate, and private key are required", ErrInvalidMaterial)
	}
	if len(request.CertificatePEM) > s.limits.MaxCertificateBytes || len(request.PrivateKeyPEM) > s.limits.MaxPrivateKeyBytes {
		return nil, ErrInputTooLarge
	}

	caCertificate, remainder, err := cert.UnmarshalCertificateFromPEM(request.CertificatePEM)
	if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, fmt.Errorf("%w: certificate PEM", ErrInvalidMaterial)
	}
	if !caCertificate.IsCA() {
		return nil, fmt.Errorf("%w: certificate is not a CA", ErrInvalidMaterial)
	}
	if caCertificate.Curve() != cert.Curve_CURVE25519 {
		return nil, ErrUnsupportedCurve
	}
	now := s.now()
	if now.Before(caCertificate.NotBefore()) || !now.Before(caCertificate.NotAfter()) {
		return nil, ErrInvalidValidity
	}
	if err := cert.NewCAPool().AddCA(caCertificate); err != nil {
		if errors.Is(err, cert.ErrExpired) {
			return nil, ErrInvalidValidity
		}
		return nil, fmt.Errorf("%w: %w", ErrInvalidMaterial, err)
	}

	rawKey, err := s.parsePrivateKey(request.PrivateKeyPEM, request.Passphrase)
	if err != nil {
		return nil, err
	}
	defer keystore.Zeroize(rawKey)
	if err := caCertificate.VerifyPrivateKey(cert.Curve_CURVE25519, rawKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKeyMismatch, err)
	}

	fingerprint, err := caCertificate.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("%w: fingerprint: %w", ErrInvalidMaterial, err)
	}
	if _, err := s.store.GetCAByFingerprint(ctx, fingerprint); err == nil {
		return nil, ErrDuplicateCA
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("look up CA fingerprint: %w", err)
	}

	caID := uuid.NewString()
	dek, wrappedDEK, err := s.master.GenerateDEK([]byte(caID))
	if err != nil {
		return nil, fmt.Errorf("generate CA data key: %w", err)
	}
	defer keystore.Zeroize(dek)
	wrappedKey, err := keystore.SealWithDEK(dek, rawKey, []byte(caID))
	if err != nil {
		return nil, fmt.Errorf("encrypt CA private key: %w", err)
	}
	canonicalPEM, err := caCertificate.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("%w: marshal certificate: %w", ErrInvalidMaterial, err)
	}

	imported := &models.CA{
		ID:                   caID,
		Name:                 name,
		OwnerOperatorID:      ownerID,
		CertPEM:              string(canonicalPEM),
		Fingerprint:          fingerprint,
		NotBefore:            caCertificate.NotBefore(),
		NotAfter:             caCertificate.NotAfter(),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      wrappedDEK.Ciphertext,
		NonceDEK:             wrappedDEK.Nonce,
		EncryptedKeyMaterial: wrappedKey.Ciphertext,
		NonceKey:             wrappedKey.Nonce,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.store.CreateCA(ctx, imported); err != nil {
		if errors.Is(err, store.ErrDuplicateEntry) {
			return nil, ErrDuplicateCA
		}
		return nil, fmt.Errorf("store imported CA: %w", err)
	}
	return imported, nil
}

func (s *Service) parsePrivateKey(privateKeyPEM, passphrase []byte) ([]byte, error) {
	block, remainder := pem.Decode(privateKeyPEM)
	if block == nil || len(bytes.TrimSpace(remainder)) != 0 {
		return nil, fmt.Errorf("%w: private key PEM", ErrInvalidMaterial)
	}

	switch block.Type {
	case cert.Ed25519PrivateKeyBanner:
		rawKey, rest, curve, err := cert.UnmarshalSigningPrivateKeyFromPEM(privateKeyPEM)
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("%w: private key", ErrInvalidMaterial)
		}
		if curve != cert.Curve_CURVE25519 {
			keystore.Zeroize(rawKey)
			return nil, ErrUnsupportedCurve
		}
		return rawKey, nil

	case cert.EncryptedEd25519PrivateKeyBanner:
		encrypted, err := cert.UnmarshalNebulaEncryptedData(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: encrypted private key metadata", ErrInvalidMaterial)
		}
		params := encrypted.EncryptionMetadata.Argon2Parameters
		if params.Memory > s.limits.MaxArgon2MemoryKiB ||
			params.Iterations > s.limits.MaxArgon2Iterations ||
			params.Parallelism > s.limits.MaxArgon2Parallelism {
			return nil, ErrKDFLimits
		}
		select {
		case s.decryptSlots <- struct{}{}:
			defer func() { <-s.decryptSlots }()
		default:
			return nil, ErrDecryptBusy
		}
		curve, rawKey, rest, err := cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, privateKeyPEM)
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			keystore.Zeroize(rawKey)
			return nil, fmt.Errorf("%w: decrypt private key", ErrInvalidMaterial)
		}
		if curve != cert.Curve_CURVE25519 {
			keystore.Zeroize(rawKey)
			return nil, ErrUnsupportedCurve
		}
		return rawKey, nil

	case cert.ECDSAP256PrivateKeyBanner, cert.EncryptedECDSAP256PrivateKeyBanner:
		return nil, ErrUnsupportedCurve

	default:
		return nil, fmt.Errorf("%w: private key type", ErrInvalidMaterial)
	}
}

func normalizeLimits(limits Limits) Limits {
	defaults := DefaultLimits()
	if limits.MaxCertificateBytes <= 0 {
		limits.MaxCertificateBytes = defaults.MaxCertificateBytes
	}
	if limits.MaxPrivateKeyBytes <= 0 {
		limits.MaxPrivateKeyBytes = defaults.MaxPrivateKeyBytes
	}
	if limits.MaxArgon2MemoryKiB == 0 {
		limits.MaxArgon2MemoryKiB = defaults.MaxArgon2MemoryKiB
	}
	if limits.MaxArgon2Iterations == 0 {
		limits.MaxArgon2Iterations = defaults.MaxArgon2Iterations
	}
	if limits.MaxArgon2Parallelism == 0 {
		limits.MaxArgon2Parallelism = defaults.MaxArgon2Parallelism
	}
	return limits
}
