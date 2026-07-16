package importproof

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateAndComputeProof(t *testing.T) {
	hostPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(hostPrivate); err != nil {
		t.Fatal(err)
	}
	hostPublic, err := curve25519.X25519(hostPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{
		SessionID: "session-1", CertificateFingerprint: "fingerprint-1",
		AgentSigningPublicKeyPEM: "signing-key", PayloadHash: "payload-hash",
	}
	challenge, expectedHash, err := Generate(rand.Reader, hostPublic, binding)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := Compute(hostPrivate, challenge.ServerPublicKey, challenge.Nonce, binding)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyHash(expectedHash, proof) {
		t.Fatal("agent proof does not match server hash")
	}

	changed := binding
	changed.PayloadHash = "substituted"
	wrong, err := Compute(hostPrivate, challenge.ServerPublicKey, challenge.Nonce, changed)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyHash(expectedHash, wrong) {
		t.Fatal("payload substitution kept the same proof")
	}
}

func TestGenerateUsesFreshEphemeralValues(t *testing.T) {
	hostPrivate := bytes.Repeat([]byte{0x42}, curve25519.ScalarSize)
	hostPublic, err := curve25519.X25519(hostPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{SessionID: "s", CertificateFingerprint: "f", AgentSigningPublicKeyPEM: "k", PayloadHash: "p"}
	first, firstHash, err := Generate(rand.Reader, hostPublic, binding)
	if err != nil {
		t.Fatal(err)
	}
	second, secondHash, err := Generate(rand.Reader, hostPublic, binding)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.ServerPublicKey, second.ServerPublicKey) || bytes.Equal(first.Nonce, second.Nonce) || firstHash == secondHash {
		t.Fatal("challenge reused an ephemeral value")
	}
}
