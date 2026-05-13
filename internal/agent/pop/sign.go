// Package pop is the agent-side proof-of-possession helper for ADR 0004
// (#75): it owns the Ed25519 signing private key, knows how to load it from
// disk, and signs poll-request canonical strings.
package pop

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

// Sign returns the Ed25519 signature over the canonical string. The caller
// is responsible for constructing the canonical string via the shared
// internal/pop.CanonicalString helper.
func Sign(privateKey ed25519.PrivateKey, canonical string) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key length = %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	return ed25519.Sign(privateKey, []byte(canonical)), nil
}

// EncodeSignature returns the base64 (standard, no-padding-stripped) form of
// the signature, suitable for the X-Nebula-Signature header.
func EncodeSignature(sig []byte) string {
	return base64.StdEncoding.EncodeToString(sig)
}

// DecodeSignature is the inverse of EncodeSignature. Reuses the same
// standard encoding; mismatched padding or non-base64 bytes return an
// error so the verifier can answer 400/401 instead of panicking.
func DecodeSignature(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("signature is empty")
	}
	return base64.StdEncoding.DecodeString(s)
}
