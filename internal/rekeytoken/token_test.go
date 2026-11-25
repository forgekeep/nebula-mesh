package rekeytoken

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestSealOpenRoundTrip(t *testing.T) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(publicKey, "nme_test-token")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(privateKey, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if opened != "nme_test-token" {
		t.Fatalf("opened token = %q", opened)
	}
}

func TestOpenRejectsWrongKeyAndTampering(t *testing.T) {
	privateKey := make([]byte, curve25519.ScalarSize)
	otherKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(otherKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := Seal(publicKey, "nme_test-token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(otherKey, sealed); err == nil {
		t.Fatal("wrong host key decrypted the token")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	decoded[len(decoded)-1] ^= 1
	tampered := base64.RawURLEncoding.EncodeToString(decoded)
	if _, err := Open(privateKey, tampered); err == nil {
		t.Fatal("tampered token decrypted successfully")
	}
}

func TestSealOpenRejectInvalidInput(t *testing.T) {
	if _, err := Seal(nil, "nme_test-token"); err == nil {
		t.Fatal("Seal accepted a missing public key")
	}
	if _, err := Seal(make([]byte, curve25519.PointSize), ""); err == nil {
		t.Fatal("Seal accepted an empty token")
	}
	if _, err := Open(nil, "ciphertext"); err == nil {
		t.Fatal("Open accepted a missing private key")
	}
	if _, err := Open(make([]byte, curve25519.ScalarSize), "not-base64!"); err == nil {
		t.Fatal("Open accepted malformed encoding")
	}
}
