package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"testing"
)

// generateSigningKeypair returns a fresh Ed25519 keypair and its PEM-encoded
// public key in the format the server expects on /api/v1/enroll.
func generateSigningKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  SigningPublicKeyPEMType,
		Bytes: pub,
	})
	return pub, priv, string(pemBytes)
}
