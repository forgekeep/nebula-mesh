package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type EnrollmentToken struct {
	ID        string     `json:"id"`
	HostID    string     `json:"host_id"`
	TokenHash string     `json:"-"` // SHA-256 hex; raw value never persisted (GHSA-ghmh-jhmj-wcmf)
	Used      bool       `json:"used"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// HashEnrollmentToken produces the at-rest representation of a raw
// enrollment token. Closes GHSA-ghmh-jhmj-wcmf: previously the raw UUID
// was stored verbatim in enrollment_tokens.token, allowing anyone with
// read access to the DB (backup, snapshot, future SQL-injection sink)
// to consume pending tokens before the legitimate agent.
//
// Symmetric: same input → same hex → constant-time DB lookup. Mirrors
// the operator_api_keys hashing already done in internal/api/middleware.go.
func HashEnrollmentToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// HashSessionToken produces the at-rest representation of a raw operator
// session token. Closes GHSA-q4vm-pq3q-8wgq: previously the raw 32-byte hex
// token was stored verbatim in operator_sessions.token and sent in the
// session cookie, so anyone with read access to the DB (backup, snapshot,
// future SQL-injection sink) could hijack every active operator session.
//
// Symmetric: same input → same hex → constant-time DB lookup. Mirrors the
// enrollment-token and operator_api_keys hashing already done elsewhere.
func HashSessionToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
