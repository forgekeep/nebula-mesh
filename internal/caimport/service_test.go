package caimport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type memoryCAStore struct {
	byID          map[string]*models.CA
	byFingerprint map[string]*models.CA
}

func newMemoryCAStore() *memoryCAStore {
	return &memoryCAStore{
		byID:          make(map[string]*models.CA),
		byFingerprint: make(map[string]*models.CA),
	}
}

func (s *memoryCAStore) CreateCA(_ context.Context, ca *models.CA) error {
	if _, exists := s.byFingerprint[ca.Fingerprint]; exists {
		return store.ErrDuplicateEntry
	}
	s.byID[ca.ID] = ca
	s.byFingerprint[ca.Fingerprint] = ca
	return nil
}

func (s *memoryCAStore) GetCA(_ context.Context, id string) (*models.CA, error) {
	ca, ok := s.byID[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return ca, nil
}

func (s *memoryCAStore) GetCAByFingerprint(_ context.Context, fingerprint string) (*models.CA, error) {
	ca, ok := s.byFingerprint[fingerprint]
	if !ok {
		return nil, store.ErrNotFound
	}
	return ca, nil
}

func TestServiceImport_UnencryptedKeyReloadsThroughResolver(t *testing.T) {
	caStore := newMemoryCAStore()
	master := testMaster(t)
	manager, certPEM, keyPEM := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	defer manager.Wipe()

	request := Request{
		Name:            "existing-mesh",
		OwnerOperatorID: "operator-1",
		CertificatePEM:  certPEM,
		PrivateKeyPEM:   keyPEM,
	}
	imported, err := NewService(caStore, master, DefaultLimits()).Import(context.Background(), request)
	require.NoError(t, err)
	require.Equal(t, models.CAStatusActive, imported.Status)
	require.Equal(t, "existing-mesh", imported.Name)
	require.NotEmpty(t, imported.EncryptedKeyDEK)
	require.NotEmpty(t, imported.EncryptedKeyMaterial)
	require.NotEqual(t, []byte(manager.RawKey()), imported.EncryptedKeyMaterial)
	requireZeroed(t, request.PrivateKeyPEM)

	loaded, err := pki.NewCAResolver(caStore, master).LoadByID(context.Background(), imported.ID)
	require.NoError(t, err)
	defer loaded.Wipe()
	wantFingerprint, err := manager.CACertFingerprint()
	require.NoError(t, err)
	gotFingerprint, err := loaded.CACertFingerprint()
	require.NoError(t, err)
	require.Equal(t, wantFingerprint, gotFingerprint)
}

func TestServiceImport_EncryptedKeyHonorsKDFLimitsAndZeroizesSecrets(t *testing.T) {
	caStore := newMemoryCAStore()
	master := testMaster(t)
	manager, certPEM, _ := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	defer manager.Wipe()

	passphrase := []byte("correct horse battery staple")
	encryptedKey, err := cert.EncryptAndMarshalSigningPrivateKey(
		cert.Curve_CURVE25519,
		manager.RawKey(),
		passphrase,
		cert.NewArgon2Parameters(64, 1, 1),
	)
	require.NoError(t, err)

	request := Request{
		Name:            "encrypted-existing-mesh",
		OwnerOperatorID: "operator-1",
		CertificatePEM:  certPEM,
		PrivateKeyPEM:   encryptedKey,
		Passphrase:      passphrase,
	}
	_, err = NewService(caStore, master, DefaultLimits()).Import(context.Background(), request)
	require.NoError(t, err)
	requireZeroed(t, request.PrivateKeyPEM)
	requireZeroed(t, request.Passphrase)

	limits := DefaultLimits()
	for _, testCase := range []struct {
		name        string
		memory      uint32
		iterations  uint32
		parallelism uint32
	}{
		{name: "memory", memory: limits.MaxArgon2MemoryKiB + 1, iterations: 1, parallelism: 1},
		{name: "iterations", memory: 64, iterations: limits.MaxArgon2Iterations + 1, parallelism: 1},
		{name: "parallelism", memory: 64, iterations: 1, parallelism: uint32(limits.MaxArgon2Parallelism) + 1},
	} {
		t.Run("over limit "+testCase.name, func(t *testing.T) {
			manager2, certPEM2, _ := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
			defer manager2.Wipe()
			encryptedKey2, err := cert.EncryptAndMarshalSigningPrivateKey(
				cert.Curve_CURVE25519,
				manager2.RawKey(),
				[]byte("passphrase"),
				cert.NewArgon2Parameters(64, 1, 1),
			)
			require.NoError(t, err)
			overLimit := rewriteArgonParams(t, encryptedKey2, testCase.memory, testCase.iterations, testCase.parallelism)

			overLimitRequest := Request{
				Name:            "too-expensive",
				OwnerOperatorID: "operator-1",
				CertificatePEM:  certPEM2,
				PrivateKeyPEM:   overLimit,
				Passphrase:      []byte("passphrase"),
			}
			_, err = NewService(caStore, master, limits).Import(context.Background(), overLimitRequest)
			require.ErrorIs(t, err, ErrKDFLimits)
			requireZeroed(t, overLimitRequest.PrivateKeyPEM)
			requireZeroed(t, overLimitRequest.Passphrase)
		})
	}
}

func TestServiceImport_EncryptedKeyRejectsBusyDecryptAndWrongPassphrase(t *testing.T) {
	t.Run("busy decrypt slot", func(t *testing.T) {
		caStore := newMemoryCAStore()
		manager, certPEM, _ := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer manager.Wipe()
		encryptedKey, err := cert.EncryptAndMarshalSigningPrivateKey(
			cert.Curve_CURVE25519,
			manager.RawKey(),
			[]byte("passphrase"),
			cert.NewArgon2Parameters(64, 1, 1),
		)
		require.NoError(t, err)

		service := NewService(caStore, testMaster(t), DefaultLimits())
		service.decryptSlots <- struct{}{}
		defer func() { <-service.decryptSlots }()
		request := Request{
			Name:            "busy",
			OwnerOperatorID: "operator-1",
			CertificatePEM:  certPEM,
			PrivateKeyPEM:   encryptedKey,
			Passphrase:      []byte("passphrase"),
		}
		_, err = service.Import(context.Background(), request)
		require.ErrorIs(t, err, ErrDecryptBusy)
		requireZeroed(t, request.PrivateKeyPEM)
		requireZeroed(t, request.Passphrase)
	})

	t.Run("wrong passphrase", func(t *testing.T) {
		manager, certPEM, _ := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer manager.Wipe()
		encryptedKey, err := cert.EncryptAndMarshalSigningPrivateKey(
			cert.Curve_CURVE25519,
			manager.RawKey(),
			[]byte("correct"),
			cert.NewArgon2Parameters(64, 1, 1),
		)
		require.NoError(t, err)

		request := Request{
			Name:            "wrong-passphrase",
			OwnerOperatorID: "operator-1",
			CertificatePEM:  certPEM,
			PrivateKeyPEM:   encryptedKey,
			Passphrase:      []byte("wrong"),
		}
		_, err = NewService(newMemoryCAStore(), testMaster(t), DefaultLimits()).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrInvalidMaterial)
		requireZeroed(t, request.PrivateKeyPEM)
		requireZeroed(t, request.Passphrase)
	})
}

func TestServiceImport_RejectsInvalidMaterial(t *testing.T) {
	master := testMaster(t)

	t.Run("non-CA certificate", func(t *testing.T) {
		issuer, _, issuerKeyPEM := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer issuer.Wipe()
		tbs := cert.TBSCertificate{
			Version:   cert.Version2,
			Name:      "host-not-ca",
			IsCA:      false,
			NotBefore: time.Now().Add(-time.Minute),
			NotAfter:  time.Now().Add(30 * time.Minute),
			PublicKey: make([]byte, 32),
			Curve:     cert.Curve_CURVE25519,
			Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		}
		hostCertificate, err := tbs.Sign(issuer.CACert(), cert.Curve_CURVE25519, issuer.RawKey())
		require.NoError(t, err)
		hostCertPEM, err := hostCertificate.MarshalPEM()
		require.NoError(t, err)
		request := Request{Name: "not-ca", OwnerOperatorID: "operator-1", CertificatePEM: hostCertPEM, PrivateKeyPEM: issuerKeyPEM}
		_, err = NewService(newMemoryCAStore(), master, DefaultLimits()).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrInvalidMaterial)
		requireZeroed(t, request.PrivateKeyPEM)
	})

	t.Run("invalid self-signature", func(t *testing.T) {
		publicKey, matchingPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, foreignPrivateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		tbs := cert.TBSCertificate{
			Version:   cert.Version2,
			Name:      "not-self-signed",
			IsCA:      true,
			NotBefore: time.Now().Add(-time.Minute),
			NotAfter:  time.Now().Add(time.Hour),
			PublicKey: publicKey,
			Curve:     cert.Curve_CURVE25519,
		}
		certificate, err := tbs.Sign(nil, cert.Curve_CURVE25519, foreignPrivateKey)
		require.NoError(t, err)
		certPEM, err := certificate.MarshalPEM()
		require.NoError(t, err)
		keyPEM := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, matchingPrivateKey)

		request := Request{Name: "not-self-signed", OwnerOperatorID: "operator-1", CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
		_, err = NewService(newMemoryCAStore(), master, DefaultLimits()).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrInvalidMaterial)
		requireZeroed(t, request.PrivateKeyPEM)
		keystore.Zeroize(matchingPrivateKey)
		keystore.Zeroize(foreignPrivateKey)
	})

	t.Run("mismatched key", func(t *testing.T) {
		manager, certPEM, _ := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer manager.Wipe()
		other, _, otherKeyPEM := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer other.Wipe()

		request := Request{Name: "mismatch", OwnerOperatorID: "operator-1", CertificatePEM: certPEM, PrivateKeyPEM: otherKeyPEM}
		_, err := NewService(newMemoryCAStore(), master, DefaultLimits()).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrKeyMismatch)
		requireZeroed(t, request.PrivateKeyPEM)
	})

	t.Run("expired certificate", func(t *testing.T) {
		manager, certPEM, keyPEM := testCA(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
		defer manager.Wipe()

		request := Request{Name: "expired", OwnerOperatorID: "operator-1", CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
		_, err := NewService(newMemoryCAStore(), master, DefaultLimits()).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrInvalidValidity)
		requireZeroed(t, request.PrivateKeyPEM)
	})

	t.Run("multiple certificate PEM blocks", func(t *testing.T) {
		manager, certPEM, keyPEM := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer manager.Wipe()

		request := Request{
			Name:            "multiple",
			OwnerOperatorID: "operator-1",
			CertificatePEM:  append(append([]byte(nil), certPEM...), certPEM...),
			PrivateKeyPEM:   keyPEM,
		}
		_, err := NewService(newMemoryCAStore(), master, DefaultLimits()).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrInvalidMaterial)
		requireZeroed(t, request.PrivateKeyPEM)
	})

	t.Run("unsupported P256 private key", func(t *testing.T) {
		manager, certPEM, _ := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer manager.Wipe()
		keyPEM := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_P256, make([]byte, 32))

		request := Request{Name: "p256", OwnerOperatorID: "operator-1", CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
		_, err := NewService(newMemoryCAStore(), master, DefaultLimits()).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrUnsupportedCurve)
		requireZeroed(t, request.PrivateKeyPEM)
	})

	t.Run("oversized private key input", func(t *testing.T) {
		manager, certPEM, keyPEM := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer manager.Wipe()
		limits := DefaultLimits()
		limits.MaxPrivateKeyBytes = len(keyPEM) - 1

		request := Request{Name: "oversized", OwnerOperatorID: "operator-1", CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
		_, err := NewService(newMemoryCAStore(), master, limits).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrInputTooLarge)
		requireZeroed(t, request.PrivateKeyPEM)
	})

	t.Run("missing master key", func(t *testing.T) {
		manager, certPEM, keyPEM := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		defer manager.Wipe()

		request := Request{Name: "no-master", OwnerOperatorID: "operator-1", CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
		_, err := NewService(newMemoryCAStore(), nil, DefaultLimits()).Import(context.Background(), request)
		require.ErrorIs(t, err, ErrMasterKeyUnavailable)
		requireZeroed(t, request.PrivateKeyPEM)
	})
}

func TestServiceImport_MapsDuplicateFingerprint(t *testing.T) {
	caStore := newMemoryCAStore()
	master := testMaster(t)
	manager, certPEM, keyPEM := testCA(t, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	defer manager.Wipe()

	first := Request{Name: "first", OwnerOperatorID: "operator-1", CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
	_, err := NewService(caStore, master, DefaultLimits()).Import(context.Background(), first)
	require.NoError(t, err)

	keyPEM = cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, manager.RawKey())
	second := Request{Name: "second", OwnerOperatorID: "operator-1", CertificatePEM: certPEM, PrivateKeyPEM: keyPEM}
	_, err = NewService(caStore, master, DefaultLimits()).Import(context.Background(), second)
	require.ErrorIs(t, err, ErrDuplicateCA)
	requireZeroed(t, second.PrivateKeyPEM)
}

func testMaster(t *testing.T) *keystore.Master {
	t.Helper()
	raw := make([]byte, keystore.MasterKeySize)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	master, err := keystore.NewMaster(raw)
	keystore.Zeroize(raw)
	require.NoError(t, err)
	return master
}

func testCA(t *testing.T, notBefore, notAfter time.Time) (manager *pki.CAManager, certPEM, keyPEM []byte) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	tbs := cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      "imported-ca",
		IsCA:      true,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		PublicKey: publicKey,
		Curve:     cert.Curve_CURVE25519,
	}
	certificate, err := tbs.Sign(nil, cert.Curve_CURVE25519, privateKey)
	require.NoError(t, err)
	certPEM, err = certificate.MarshalPEM()
	require.NoError(t, err)
	manager, err = pki.LoadCAFromMaterial(certPEM, privateKey)
	require.NoError(t, err)
	keyPEM = cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, privateKey)
	return manager, certPEM, keyPEM
}

func rewriteArgonParams(t *testing.T, encryptedKey []byte, memory, iterations, parallelism uint32) []byte {
	t.Helper()
	block, rest := pem.Decode(encryptedKey)
	require.NotNil(t, block)
	require.Empty(t, rest)
	var raw cert.RawNebulaEncryptedData
	require.NoError(t, proto.Unmarshal(block.Bytes, &raw))
	require.NotNil(t, raw.EncryptionMetadata)
	require.NotNil(t, raw.EncryptionMetadata.Argon2Parameters)
	raw.EncryptionMetadata.Argon2Parameters.Memory = memory
	raw.EncryptionMetadata.Argon2Parameters.Iterations = iterations
	raw.EncryptionMetadata.Argon2Parameters.Parallelism = parallelism
	encoded, err := proto.Marshal(&raw)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: encoded})
}

func requireZeroed(t *testing.T, value []byte) {
	t.Helper()
	for _, b := range value {
		if b != 0 {
			t.Fatalf("secret buffer was not zeroized")
		}
	}
}
