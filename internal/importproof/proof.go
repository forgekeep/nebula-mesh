// Package importproof implements the one-time X25519 proof used while adopting
// an existing Nebula host. It proves possession of host.key without uploading
// the private key and binds the proof to the exact registration payload.
package importproof

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

const domain = "nebula-mesh-import-proof-v1"

type Binding struct {
	SessionID                string
	CertificateFingerprint   string
	AgentSigningPublicKeyPEM string
	PayloadHash              string
}

type Challenge struct {
	ServerPublicKey []byte
	Nonce           []byte
}

func Generate(random io.Reader, hostPublicKey []byte, binding Binding) (Challenge, string, error) {
	if random == nil || len(hostPublicKey) != curve25519.PointSize || !validBinding(binding) {
		return Challenge{}, "", errors.New("complete import proof input is required")
	}
	serverPrivate := make([]byte, curve25519.ScalarSize)
	defer clear(serverPrivate)
	if _, err := io.ReadFull(random, serverPrivate); err != nil {
		return Challenge{}, "", err
	}
	serverPublic, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
	if err != nil {
		return Challenge{}, "", err
	}
	shared, err := curve25519.X25519(serverPrivate, hostPublicKey)
	if err != nil {
		return Challenge{}, "", err
	}
	defer clear(shared)
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return Challenge{}, "", err
	}
	proof := calculate(shared, nonce, binding)
	defer clear(proof)
	return Challenge{ServerPublicKey: serverPublic, Nonce: nonce}, ProofHash(proof), nil
}

func Compute(hostPrivateKey, serverPublicKey, nonce []byte, binding Binding) ([]byte, error) {
	if len(hostPrivateKey) != curve25519.ScalarSize || len(serverPublicKey) != curve25519.PointSize || len(nonce) != 32 || !validBinding(binding) {
		return nil, errors.New("complete import proof input is required")
	}
	shared, err := curve25519.X25519(hostPrivateKey, serverPublicKey)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	return calculate(shared, nonce, binding), nil
}

func ProofHash(proof []byte) string {
	sum := sha256.Sum256(proof)
	return hex.EncodeToString(sum[:])
}

func VerifyHash(expectedHash string, proof []byte) bool {
	expected, err := hex.DecodeString(expectedHash)
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256(proof)
	return subtle.ConstantTimeCompare(expected, actual[:]) == 1
}

func calculate(shared, nonce []byte, binding Binding) []byte {
	signingHash := sha256.Sum256([]byte(binding.AgentSigningPublicKeyPEM))
	mac := hmac.New(sha256.New, shared)
	writeField(mac, domain)
	writeField(mac, binding.SessionID)
	writeField(mac, binding.CertificateFingerprint)
	writeField(mac, hex.EncodeToString(signingHash[:]))
	writeField(mac, binding.PayloadHash)
	_, _ = mac.Write(nonce)
	return mac.Sum(nil)
}

func writeField(writer io.Writer, value string) {
	_, _ = io.WriteString(writer, value)
	_, _ = writer.Write([]byte{0})
}

func validBinding(binding Binding) bool {
	return binding.SessionID != "" && binding.CertificateFingerprint != "" &&
		binding.AgentSigningPublicKeyPEM != "" && binding.PayloadHash != ""
}
