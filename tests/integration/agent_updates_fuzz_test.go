package integration

import (
	"io"
	"net/http"
	"testing"

	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
)

// FuzzAgentUpdatesHeaders fuzzes the four proof-of-possession headers on GET
// /api/v1/agent/updates with a *real enrolled host's* fingerprint provisioned by
// the harness (ADR 0009 Tier 1, ADR 0004 §7.1). Pinning a valid fingerprint
// carries the corpus past the host lookup into the verification core: signature
// base64-decode, canonical-string assembly, ed25519 verify, RFC3339 timestamp
// validation, and the nonce-replay cache. No fuzzed signature can match the
// host's bound key, so the handler must never 5xx (chi's Recoverer surfaces a
// panic, bar http.ErrAbortHandler, as a 500) and never 2xx (no forged poll
// authenticates).
//
//	go test ./tests/integration/ -run '^$' -fuzz='^FuzzAgentUpdatesHeaders$'
func FuzzAgentUpdatesHeaders(f *testing.F) {
	ts, _, _ := setupE2E(f)
	_, fingerprint := enrollHostForFuzz(f, ts)

	// Seeds pin the real fingerprint so the corpus reaches signature verification;
	// none carries a valid signature, so none authenticates.
	f.Add(fingerprint, "2026-05-27T00:00:00Z", "bm9uY2U=", "c2ln")
	f.Add(fingerprint, "not-a-time", "n", "!!!notbase64")
	f.Add("deadbeefdeadbeef", "2026-05-27T00:00:00Z", "bm9uY2U=", "AAAA")
	f.Add("", "", "", "")

	f.Fuzz(func(t *testing.T, fpHdr, timestamp, nonce, signature string) {
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/agent/updates", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set(corepop.HeaderFingerprint, fpHdr)
		req.Header.Set(corepop.HeaderTimestamp, timestamp)
		req.Header.Set(corepop.HeaderNonce, nonce)
		req.Header.Set(corepop.HeaderSignature, signature)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return // client refused an invalid header value, or transport error
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode/100 == 5 {
			t.Fatalf("agent/updates returned %d on fuzzed PoP headers (server fault)", resp.StatusCode)
		}
		if resp.StatusCode/100 == 2 {
			t.Fatalf("agent/updates returned %d — a fuzzed signature authenticated", resp.StatusCode)
		}
	})
}
