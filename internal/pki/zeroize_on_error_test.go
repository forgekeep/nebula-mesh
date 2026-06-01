package pki

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"
)

// TestLoadCAOrZeroize_WipesKeyOnError verifies that when CAManager construction
// fails after the key has already been decrypted, the plaintext key bytes are
// zeroized rather than left on the heap (#181).
func TestLoadCAOrZeroize_WipesKeyOnError(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, ed25519.PrivateKeySize)

	mgr, err := loadCAOrZeroize([]byte("-----BEGIN GARBAGE-----\nnope\n-----END GARBAGE-----\n"), key)
	if err == nil {
		t.Fatal("expected error for unparseable cert PEM")
	}
	if mgr != nil {
		t.Fatalf("expected nil manager on error, got %v", mgr)
	}
	for i, b := range key {
		if b != 0 {
			t.Fatalf("key not zeroized on error path: byte %d = %#x", i, b)
		}
	}
}

// TestLoadCAOrZeroize_PreservesKeyOnSuccess verifies the success path transfers
// the key to the manager intact — the fix must NOT wipe a live signing key.
func TestLoadCAOrZeroize_PreservesKeyOnSuccess(t *testing.T) {
	src, err := NewCA("zeroize-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := src.CACertPEM()
	if err != nil {
		t.Fatal(err)
	}
	key := append(ed25519.PrivateKey(nil), src.RawKey()...) // copy so we own it

	mgr, err := loadCAOrZeroize(certPEM, key)
	if err != nil {
		t.Fatalf("unexpected error on valid material: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected a manager on success")
	}
	if allZero(key) {
		t.Fatal("success path wiped the key — would break signing")
	}
	// The manager must hold the same (aliased) key, ready to sign.
	if !bytes.Equal(mgr.RawKey(), key) {
		t.Fatal("manager key does not match input key")
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
