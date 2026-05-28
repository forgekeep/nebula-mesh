package pop_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	agentpop "github.com/forgekeep/nebula-mesh/internal/agent/pop"
	apipop "github.com/forgekeep/nebula-mesh/internal/api/pop"
	"github.com/forgekeep/nebula-mesh/internal/pop"
)

// FuzzPoPCanonical exercises the proof-of-possession canonical string (ADR
// 0004 §7.1) — the bytes every signed poll is authenticated over. Two
// properties matter for auth soundness:
//
//  1. Injectivity. CanonicalString joins five fields with "\n" and escapes
//     nothing, so the encoding is unambiguous *only* while no field contains
//     the separator. For separator-free inputs, splitting the result on "\n"
//     must recover the exact five fields — otherwise two distinct
//     (method, path, host, timestamp, nonce) tuples could share one signed
//     message, an auth-equivalence the verifier cannot see. The ADR flags the
//     unescaped join as a latent fragility; this pins the safe envelope and
//     catches any future change that narrows or breaks it.
//
//  2. Sign/verify agreement. A signature the agent produces over the canonical
//     string must verify on the server; any tamper or wrong key must be
//     rejected with ErrBadSignature — never a panic, never a false accept.
//
// Run the seed corpus with the unit tests; explore with
//
//	go test ./internal/pop/ -run '^$' -fuzz='^FuzzPoPCanonical$'
func FuzzPoPCanonical(f *testing.F) {
	// One keypair for the whole run: key generation is not under test, and
	// ed25519 verification is deterministic in the message + key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	// Seeds: a real poll, the all-empty tuple, an embedded-separator field
	// (exercises the non-injective branch), and an enroll-shaped POST.
	f.Add("GET", "/api/v1/agent/updates", "mgmt.example:443", "2026-05-27T00:00:00Z", "bm9uY2U=")
	f.Add("", "", "", "", "")
	f.Add("GET", "/a\nb", "h", "t", "n")
	f.Add("POST", "/api/v1/enroll", "h:8080", "2026-05-27T00:00:00Z", "")

	f.Fuzz(func(t *testing.T, method, path, host, timestamp, nonce string) {
		canonical := pop.CanonicalString(method, path, host, timestamp, nonce)

		// (1) Injectivity holds exactly when no field carries the separator.
		fields := []string{method, path, host, timestamp, nonce}
		separatorFree := true
		for _, fld := range fields {
			if strings.Contains(fld, "\n") {
				separatorFree = false
				break
			}
		}
		if separatorFree {
			got := strings.Split(canonical, "\n")
			if len(got) != len(fields) {
				t.Fatalf("separator-free input split into %d fields, want %d\ncanonical=%q", len(got), len(fields), canonical)
			}
			for i := range fields {
				if got[i] != fields[i] {
					t.Fatalf("field %d not recovered: got %q want %q\ncanonical=%q", i, got[i], fields[i], canonical)
				}
			}
		}

		// (2) Sign/verify round-trip, plus rejection of wrong key and tamper.
		sig, err := agentpop.Sign(priv, canonical)
		if err != nil {
			t.Fatalf("Sign errored on canonical string: %v", err)
		}
		if err := apipop.Verify(pub, canonical, sig); err != nil {
			t.Fatalf("Verify rejected a freshly signed canonical string: %v\ncanonical=%q", err, canonical)
		}
		if err := apipop.Verify(otherPub, canonical, sig); err == nil {
			t.Fatalf("Verify accepted a signature under the wrong key\ncanonical=%q", canonical)
		}
		// Appending any byte changes the signed message, so the same signature
		// must no longer verify.
		if err := apipop.Verify(pub, canonical+"x", sig); err == nil {
			t.Fatalf("Verify accepted a tampered canonical string\ncanonical=%q", canonical)
		}
	})
}
