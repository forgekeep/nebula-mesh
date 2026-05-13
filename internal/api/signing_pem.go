package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// decodeSigBase64 is the inverse of agent-side EncodeSignature; standard
// base64 with required padding.
func decodeSigBase64(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty signature")
	}
	return base64.StdEncoding.DecodeString(s)
}

// SigningPublicKeyPEMType is the PEM block type used by the agent for its
// Ed25519 poll-signature public key (ADR 0004 §7.1). Distinct from the X25519
// `NEBULA X25519 PRIVATE KEY` / `NEBULA X25519 PUBLIC KEY` banners that
// slackhq/nebula/cert owns.
const SigningPublicKeyPEMType = "NEBULA ED25519 PUBLIC KEY"

// decodeSigningPublicKeyPEM parses an Ed25519 public key from its PEM-wrapped
// raw 32-byte representation. Returns ErrBadSigningPEM on shape mismatch so
// callers map it to 400.
func decodeSigningPublicKeyPEM(pemStr string) (ed25519.PublicKey, error) {
	if pemStr == "" {
		return nil, ErrBadSigningPEM
	}
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != SigningPublicKeyPEMType {
		return nil, ErrBadSigningPEM
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, ErrBadSigningPEM
	}
	return ed25519.PublicKey(block.Bytes), nil
}

// ErrBadSigningPEM is returned when an Ed25519 signing public key PEM is
// missing, the wrong block type, or the wrong byte length.
var ErrBadSigningPEM = errors.New("bad signing public key PEM")
