package pki_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

// resolver.go had no test file, yet LoadByID is the key-decryption path: it
// unwraps the DEK with the master key, opens the AEAD-sealed signing key, and
// hands back a live CAManager. These tests pin that the round-trip recovers
// the real key (not garbage that merely parsed), that a wiped manager can no
// longer mint trusted certs ON THIS path (the GHSA-8h84 contract where it
// matters most), that distinct CAs never share key material, and that every
// decryption failure surfaces as an error rather than a usable-but-wrong CA.

// mintCAInStore seeds an operator and mints+stores a CA owned by it, returning
// the persisted CA row (with its encrypted key material).
func mintCAInStore(t *testing.T, s store.Store, master *keystore.Master, opID string) *models.CA {
	t.Helper()
	op := seedOperator(t, s, opID, opID)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, _, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     opID + "-ca",
		Duration: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("MintAndStoreCA: %v", err)
	}
	return c
}

func mintResolverCA(t *testing.T, opID string) (store.Store, *models.CA, *keystore.Master) {
	t.Helper()
	s := newTestStore(t)
	m := newTestMaster(t)
	return s, mintCAInStore(t, s, m, opID), m
}

// hostPubKey returns a fresh X25519 public key for a host SignRequest.
func hostPubKey(t *testing.T) []byte {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestCAResolver_LoadByID_RoundTripRecoversSigningKey(t *testing.T) {
	s, ca, master := mintResolverCA(t, "op-roundtrip")

	mgr, err := pki.NewCAResolver(s, master).LoadByID(context.Background(), ca.ID)
	if err != nil {
		t.Fatalf("LoadByID: %v", err)
	}

	// The decrypted private key must correspond to the stored CA cert's
	// public key. A wrong-but-valid key would still parse, so comparing the
	// derived public key is what actually proves the DEK-unwrap + AEAD-open
	// recovered the genuine signing key.
	rawKey := mgr.RawKey()
	if len(rawKey) != ed25519.PrivateKeySize {
		t.Fatalf("RawKey length = %d, want %d", len(rawKey), ed25519.PrivateKeySize)
	}
	derivedPub, ok := rawKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("RawKey.Public() is not ed25519.PublicKey")
	}
	if !bytes.Equal(derivedPub, mgr.CACert().PublicKey()) {
		t.Error("decrypted private key does not match the stored CA cert public key")
	}

	fp, err := mgr.CACertFingerprint()
	if err != nil {
		t.Fatalf("CACertFingerprint: %v", err)
	}
	if fp != ca.Fingerprint {
		t.Errorf("fingerprint = %q, want %q", fp, ca.Fingerprint)
	}
}

// TestCAResolver_LoadByID_WipedManagerCannotMintVerifiableCert is the
// behavioral GHSA-8h84 pin on the decryption path specifically: a manager
// returned by LoadByID, once Wiped, must not be able to mint a cert that
// verifies against its own CA. This complements the NewCA-path assertion in
// signer_property_test.go — the two construction paths build CAManager
// differently (NewCA vs LoadCAFromMaterial), so a regression that made
// LoadCAFromMaterial copy the key into a non-aliased buffer would defeat the
// byte-zero check below yet be caught here.
func TestCAResolver_LoadByID_WipedManagerCannotMintVerifiableCert(t *testing.T) {
	s, ca, master := mintResolverCA(t, "op-wipe-sign")

	mgr, err := pki.NewCAResolver(s, master).LoadByID(context.Background(), ca.ID)
	if err != nil {
		t.Fatalf("LoadByID: %v", err)
	}
	certPEM, err := mgr.CACertPEM()
	if err != nil {
		t.Fatalf("CACertPEM: %v", err)
	}
	pool, err := cert.NewCAPoolFromPEM(certPEM)
	if err != nil {
		t.Fatalf("NewCAPoolFromPEM: %v", err)
	}
	req := pki.SignRequest{
		Name:      "host",
		PublicKey: hostPubKey(t),
		Networks:  []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
		Duration:  time.Hour,
	}

	// Positive control: the live decrypted key mints a verifiable cert.
	good, err := mgr.Sign(req)
	if err != nil {
		t.Fatalf("Sign (pre-wipe): %v", err)
	}
	if _, err := pool.VerifyCertificate(time.Now(), good); err != nil {
		t.Fatalf("pre-wipe cert failed to verify: %v", err)
	}

	mgr.Wipe()

	bad, err := mgr.Sign(req)
	if err != nil {
		return // defensive: a future guard could refuse to sign with a wiped key
	}
	if _, err := pool.VerifyCertificate(time.Now(), bad); err == nil {
		t.Error("cert signed after Wipe() verified — decrypted key survived Wipe on the resolver path")
	}
}

// TestCAResolver_LoadByID_DistinctCAsDoNotShareKeys pins two properties of the
// resolver's no-cache contract (documented on CAResolver): each CA decrypts to
// its own key bound to its own cert, and Wiping one manager does not affect
// another — i.e. LoadByID returns independent key material per call rather
// than handing out aliases of a shared/cached buffer.
func TestCAResolver_LoadByID_DistinctCAsDoNotShareKeys(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	caA := mintCAInStore(t, s, master, "op-dist-a")
	caB := mintCAInStore(t, s, master, "op-dist-b")

	resolver := pki.NewCAResolver(s, master)
	mgrA, err := resolver.LoadByID(context.Background(), caA.ID)
	if err != nil {
		t.Fatalf("LoadByID A: %v", err)
	}
	mgrB, err := resolver.LoadByID(context.Background(), caB.ID)
	if err != nil {
		t.Fatalf("LoadByID B: %v", err)
	}

	// Each manager's key matches its own cert and not the other's.
	pubA := mgrA.RawKey().Public().(ed25519.PublicKey)
	pubB := mgrB.RawKey().Public().(ed25519.PublicKey)
	if !bytes.Equal(pubA, mgrA.CACert().PublicKey()) || !bytes.Equal(pubB, mgrB.CACert().PublicKey()) {
		t.Fatal("a manager's decrypted key does not match its own CA cert")
	}
	if bytes.Equal(pubA, pubB) {
		t.Fatal("two distinct CAs resolved to the same key")
	}

	// Wiping A must not disturb B — proves the managers don't alias shared
	// (e.g. cached) key material.
	mgrA.Wipe()
	allZero := true
	for _, b := range mgrB.RawKey() {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Wiping CA A zeroed CA B's key — resolver is sharing key material across calls")
	}
}

func TestCAResolver_LoadByID_WipeZeroesReturnedKey(t *testing.T) {
	s, ca, master := mintResolverCA(t, "op-wipe")

	mgr, err := pki.NewCAResolver(s, master).LoadByID(context.Background(), ca.ID)
	if err != nil {
		t.Fatalf("LoadByID: %v", err)
	}

	// RawKey aliases the manager's in-memory key, so Wipe must zero it in
	// place — pinning the GHSA-8h84 "don't leave the key on the heap" contract
	// for the resolver path specifically.
	rawKey := mgr.RawKey()
	mgr.Wipe()
	for i, b := range rawKey {
		if b != 0 {
			t.Fatalf("byte %d not zeroed after Wipe: got %d", i, b)
		}
	}
}

func TestCAResolver_LoadByID_UnknownCA(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	if _, err := pki.NewCAResolver(s, master).LoadByID(context.Background(), "does-not-exist"); err == nil {
		t.Error("LoadByID for unknown CA: want error, got nil")
	}
}

func TestCAResolver_LoadByID_NilReceiverAndNilMaster(t *testing.T) {
	var nilResolver *pki.CAResolver
	if _, err := nilResolver.LoadByID(context.Background(), "x"); err == nil {
		t.Error("nil resolver: want error, got nil")
	}

	s := newTestStore(t)
	if _, err := pki.NewCAResolver(s, nil).LoadByID(context.Background(), "x"); err == nil {
		t.Error("nil master: want error, got nil")
	}
}

// fakeCAStore returns a fixed CA row for any id, so the decryption error paths
// can be exercised with deliberately corrupted key material.
type fakeCAStore struct{ ca *models.CA }

func (f fakeCAStore) GetCA(context.Context, string) (*models.CA, error) { return f.ca, nil }

func TestCAResolver_LoadByID_CorruptedKeyMaterialFails(t *testing.T) {
	_, ca, master := mintResolverCA(t, "op-tamper")

	for _, tc := range []struct {
		name   string
		tamper func(c *models.CA)
	}{
		{"corrupt DEK wrap", func(c *models.CA) { c.EncryptedKeyDEK[0] ^= 0xFF }},
		{"corrupt key material", func(c *models.CA) { c.EncryptedKeyMaterial[0] ^= 0xFF }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := *ca
			bad.EncryptedKeyDEK = append([]byte(nil), ca.EncryptedKeyDEK...)
			bad.EncryptedKeyMaterial = append([]byte(nil), ca.EncryptedKeyMaterial...)
			tc.tamper(&bad)

			if _, err := pki.NewCAResolver(fakeCAStore{ca: &bad}, master).LoadByID(context.Background(), ca.ID); err == nil {
				t.Errorf("%s: LoadByID returned a manager from corrupted material, want error", tc.name)
			}
		})
	}
}
