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
	// 401s — no token is minted.
	if _, signingPub, err := ed25519.GenerateKey(rand.Reader); err == nil {
		signingPEM := pem.EncodeToMemory(&pem.Block{Type: "NEBULA ED25519 PUBLIC KEY", Bytes: signingPub})
		if seed, mErr := json.Marshal(map[string]string{
			"token":                  "bogus-but-well-formed",
			"public_key_pem":         "non-empty",
			"signing_public_key_pem": string(signingPEM),
		}); mErr == nil {
			f.Add(seed)
		}
	}

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
