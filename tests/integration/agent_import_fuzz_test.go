package integration

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

// FuzzAgentImportPayload exercises both public import endpoints without
// provisioning an import token. Arbitrary input must not panic the server and
// must never create an imported identity.
//
//	go test ./tests/integration -run '^$' -fuzz='^FuzzAgentImportPayload$'
func FuzzAgentImportPayload(f *testing.F) {
	ts, _, _ := setupE2E(f)

	f.Add(false, []byte(`{}`))
	f.Add(false, []byte(`{"token":"bogus","certificate_pem":"not-a-certificate"}`))
	f.Add(true, []byte(`{}`))
	f.Add(true, []byte(`{"token":"bogus","challenge_id":"bogus","signature":"bogus"}`))
	f.Add(true, []byte(`not json`))

	f.Fuzz(func(t *testing.T, register bool, body []byte) {
		path := "/api/v1/agent/import/challenge"
		if register {
			path = "/api/v1/agent/import"
		}
		resp, err := http.Post(ts.URL+path, "application/json", bytes.NewReader(body))
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode/100 == 5 {
			t.Fatalf("%s returned server error %d for body %q", path, resp.StatusCode, body)
		}
		if resp.StatusCode/100 == 2 {
			t.Fatalf("%s accepted a request without a valid import token: %d, body %q", path, resp.StatusCode, body)
		}
	})
}
