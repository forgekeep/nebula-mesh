// Package pop holds the server-side proof-of-possession verifier and the
// per-(host, nonce) replay cache used by the signed-poll handler (ADR 0004).
package pop

import (
	"crypto/ed25519"
	"errors"
)

// ErrBadSignature is returned when the signature does not verify, either
// because the canonical message was tampered, the public key does not match
// the host, or the key/signature length is wrong. The poll handler maps it
// to a 401 with reason=bad_signature.
var ErrBadSignature = errors.New("bad signature")

// Verify checks the Ed25519 signature over the canonical string. All length
// validation happens here so the handler can call Verify uniformly.
func Verify(publicKey ed25519.PublicKey, canonical string, sig []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrBadSignature
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(publicKey, []byte(canonical), sig) {
		return ErrBadSignature
	}
	return nil
}
