// Package pop holds the proof-of-possession primitives shared by the agent
// (signer) and the management server (verifier) for ADR 0004 #75 polls.
//
// The canonical string is signed by the agent's Ed25519 signing key and
// transported in the X-Nebula-Signature header alongside the fingerprint,
// timestamp, and nonce. The format is intentionally rigid — four "\n"
// separators between five trusted server-shaped fields — so a single
// implementation works for sign and verify and a golden test can pin it.
package pop

// Header names used in the signed-poll protocol (ADR 0004 §7.1).
const (
	HeaderFingerprint = "X-Nebula-Fingerprint"
	HeaderTimestamp   = "X-Nebula-Timestamp"
	HeaderNonce       = "X-Nebula-Nonce"
	HeaderSignature   = "X-Nebula-Signature"
)

// CanonicalString returns the bytes that the agent signs and the server
// verifies for every poll request. Format:
//
//	METHOD\nPATH\nHOST_HEADER\nTIMESTAMP\nNONCE
//
// All inputs are caller-trusted: METHOD and PATH come from the chi router,
// HOST_HEADER from the Host header, and TIMESTAMP / NONCE from the request
// headers (already syntactically validated by the verifier before this is
// computed on the server side).
func CanonicalString(method, path, host, timestamp, nonce string) string {
	return method + "\n" + path + "\n" + host + "\n" + timestamp + "\n" + nonce
}
