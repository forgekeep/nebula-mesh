package models

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestHashEnrollmentToken_StableAndDoesNotLeak pins the contract that
// closes GHSA-ghmh-jhmj-wcmf: the at-rest token hash must be a
// deterministic SHA-256 hex digest of the raw input, distinct from the
// input (no echo), and stable across calls. Inspired by netbird's
// session_test.go::TestHashToken_StableAndDoesNotLeak.
func TestHashEnrollmentToken_StableAndDoesNotLeak(t *testing.T) {
	const raw = "550e8400-e29b-41d4-a716-446655440000" // UUID-shaped sample input
	got := HashEnrollmentToken(raw)

	// Deterministic — same input, same output.
	if again := HashEnrollmentToken(raw); got != again {
		t.Errorf("hash is non-deterministic: %q vs %q", got, again)
	}

	// Does not leak: the digest must not contain the raw input as a
	// substring. SHA-256 hex output is 64 lowercase hex chars; a UUID
	// has dashes and is 36 chars — they can't collide accidentally,
	// but the assertion captures intent.
	if strings.Contains(got, raw) {
		t.Errorf("hash %q contains raw input %q", got, raw)
	}

	// SHA-256 hex shape: 64 lowercase hex chars.
	if len(got) != 2*sha256.Size {
		t.Errorf("hash length = %d, want %d (SHA-256 hex)", len(got), 2*sha256.Size)
	}
	for _, r := range got {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			continue
		}
		t.Errorf("hash contains non-lowercase-hex character %q", r)
		break
	}

	// Computing the digest the long way must match.
	sum := sha256.Sum256([]byte(raw))
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Errorf("hash = %q, want %q (independent SHA-256)", got, want)
	}
}

// TestHashEnrollmentToken_DistinguishesNeighbors asserts that small
// input differences map to distinct outputs. Trivially true for any
// cryptographic hash, but pins the dependency on a real hash function
// (vs e.g. a stub that returns the raw input).
func TestHashEnrollmentToken_DistinguishesNeighbors(t *testing.T) {
	inputs := []string{
		"",
		"a",
		"A",
		"aa",
		"550e8400-e29b-41d4-a716-446655440000",
		"550e8400-e29b-41d4-a716-446655440001", // last hex flipped
		"550e8400-e29b-41d4-a716-44665544000",  // truncated
	}
	seen := map[string]string{}
	for _, in := range inputs {
		h := HashEnrollmentToken(in)
		if prev, ok := seen[h]; ok {
			t.Errorf("collision: %q and %q both hash to %q", prev, in, h)
		}
		seen[h] = in
	}
}

// TestHashEnrollmentToken_EmptyInput pins the behavior on empty input.
// The function does not reject empty strings (callers are responsible
// for validating token shape upstream) — it produces the SHA-256 of
// the empty string, which is a well-known constant. Captured so a
// future "reject empty" refactor is a deliberate decision.
func TestHashEnrollmentToken_EmptyInput(t *testing.T) {
	got := HashEnrollmentToken("")
	const sha256OfEmpty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != sha256OfEmpty {
		t.Errorf("hash of empty = %q, want %q", got, sha256OfEmpty)
	}
}
