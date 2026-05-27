package integration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"testing"
)

// FuzzEnrollPayload feeds arbitrary bytes to the public POST /api/v1/enroll
// handler (ADR 0009 Tier 1). The harness mints no token, so no input can
// complete an enrollment. This is an honest robustness guard, not a deep target:
// the body-handling is thin glue (JSON decode, non-empty guards, the Ed25519
// signing-PEM decoder), while the cert-signing and config-render work sits
// behind the single-use-token gate and operates on stored host state — not
// reachable from the body. Every garbage body must draw a client error: never a
// 5xx (chi's Recoverer surfaces a panic, bar http.ErrAbortHandler, as a 500) and
// never a 2xx (no certificate without a valid token). The PoP verify core is
// fuzzed by FuzzAgentUpdatesHeaders; host-creation validation is tracked as a
// follow-up fuzz target.
//
//	go test ./tests/integration/ -run '^$' -fuzz='^FuzzEnrollPayload$'
func FuzzEnrollPayload(f *testing.F) {
	ts, _, _ := setupE2E(f)

	f.Add([]byte(`{"token":"t","public_key_pem":"-----BEGIN NEBULA X25519 PUBLIC KEY-----\nAA==\n-----END NEBULA X25519 PUBLIC KEY-----","signing_public_key_pem":"x"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"token":"","public_key_pem":""}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(``))

	// A well-formed seed (valid signing PEM, non-empty token+pubkey) so the
	// corpus clears the early guards and reaches enrollment-token lookup, which
	// 401s — no token is minted. TestEnrollWellFormedSeedReaches401 pins that
	// depth, since the never-5xx/never-2xx assertion below cannot.
	f.Add(wellFormedEnrollSeed(f))

	f.Fuzz(func(t *testing.T, body []byte) {
		resp, err := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(body))
		if err != nil {
			return // transport/client-side rejection — not a server fault
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode/100 == 5 {
			t.Fatalf("enroll returned %d on fuzzed body (server fault); body=%q", resp.StatusCode, body)
		}
		if resp.StatusCode/100 == 2 {
			t.Fatalf("enroll returned %d — a certificate completed without a valid token; body=%q", resp.StatusCode, body)
		}
	})
}

// wellFormedEnrollSeed builds an enroll payload that clears all three early 400
// guards in handleEnroll — JSON decode, the non-empty token+public_key_pem
// check, and the Ed25519 signing-PEM decoder (which requires exactly
// ed25519.PublicKeySize bytes) — with a deliberately bogus token, so the request
// then 401s at enrollment-token lookup. It is shared by the FuzzEnrollPayload
// seed corpus and TestEnrollWellFormedSeedReaches401 so the two cannot drift.
//
// The signing key must be the public half. ed25519.GenerateKey returns
// (PublicKey, PrivateKey, error) — public first; binding the private half (64
// bytes) instead fails the 32-byte signing-PEM guard and the request stops at a
// 400, which still satisfies the fuzz never-5xx/never-2xx assertion. That silent
// degradation is exactly what TestEnrollWellFormedSeedReaches401 guards against.
func wellFormedEnrollSeed(tb testing.TB) []byte {
	tb.Helper()
	signingPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatalf("generate signing key: %v", err)
	}
	signingPEM := pem.EncodeToMemory(&pem.Block{Type: "NEBULA ED25519 PUBLIC KEY", Bytes: signingPub})
	seed, err := json.Marshal(map[string]string{
		"token":                  "bogus-but-well-formed",
		"public_key_pem":         "non-empty",
		"signing_public_key_pem": string(signingPEM),
	})
	if err != nil {
		tb.Fatalf("marshal enroll seed: %v", err)
	}
	return seed
}

// TestEnrollWellFormedSeedReaches401 pins the depth the FuzzEnrollPayload
// well-formed seed depends on: the payload must clear the early 400 guards and
// reach enrollment-token lookup, which 401s on the bogus token. The fuzz
// assertion alone cannot see this — 400 and 401 both satisfy never-5xx/never-2xx
// — so a seed that silently stops at a 400 guard would still pass the fuzz. This
// test fails loudly instead.
func TestEnrollWellFormedSeedReaches401(t *testing.T) {
	ts, _, _ := setupE2E(t)

	resp, err := http.Post(ts.URL+"/api/v1/enroll", "application/json", bytes.NewReader(wellFormedEnrollSeed(t)))
	if err != nil {
		t.Fatalf("POST enroll: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("well-formed enroll seed: got %d, want 401 — the seed must clear the early 400 guards "+
			"(JSON, non-empty, 32-byte signing PEM) and reach enrollment-token lookup; a 400 means it "+
			"silently degraded to a generic malformed input", resp.StatusCode)
	}
}
