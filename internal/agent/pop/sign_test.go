package pop

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
)

func TestSign_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical := corepop.CanonicalString("GET", "/p", "h", "2026-05-13T08:30:00Z", "n")
	sig, err := Sign(priv, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatal("Verify failed for round-trip")
	}
}

func TestSign_WrongKeyDoesNotVerify(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	canonical := corepop.CanonicalString("GET", "/p", "h", "ts", "n")
	sig, err := Sign(priv, canonical)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(otherPub, []byte(canonical), sig) {
		t.Fatal("Verify accepted signature under the wrong public key")
	}
}

func TestSign_BadPrivateKeyLength(t *testing.T) {
	if _, err := Sign(make([]byte, 10), "anything"); err == nil {
		t.Fatal("expected error for short private key")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig, err := Sign(priv, "msg")
	if err != nil {
		t.Fatal(err)
	}
	encoded := EncodeSignature(sig)
	if encoded == "" {
		t.Fatal("encoded empty")
	}
	decoded, err := DecodeSignature(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(sig) {
		t.Fatal("round-trip mismatch")
	}
}

func TestDecodeSignature_RejectsBase64Garbage(t *testing.T) {
	if _, err := DecodeSignature("!!!not base64!!!"); err == nil {
		t.Fatal("expected error")
	}
}
