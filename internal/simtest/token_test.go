package simtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"sync"
	"testing"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// TestSim_TokenSingleUse asserts the TOKEN_SINGLE_USE invariant from ADR 0009:
// a single enrollment token can be redeemed exactly once, even under
// concurrent redemption. A double-redeem means two agents obtain valid certs
// for one host identity.
//
// Runs against a file-backed store (WithFileStore): the :memory: store pins
// MaxOpenConns(1) and would serialize the ConsumeToken transactions, masking
// any race. ConsumeToken is a single SELECT-check-UPDATE transaction, so WAL
// snapshot isolation should let exactly one redemption win — this test
// confirms that holds rather than assuming it.
func TestSim_TokenSingleUse(t *testing.T) {
	h := New(t, WithFileStore())
	netID := h.CreateNetwork("token-net", "10.30.0.0/16")
	_, token := h.CreateHost(netID, "lonely-host", "", "10.30.0.7")

	const n = 16
	start := make(chan struct{})
	codes := make([]int, n)
	gotCert := make([]bool, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each redeemer brings its own keypairs.
			priv := make([]byte, 32)
			if _, err := rand.Read(priv); err != nil {
				errs[i] = err
				return
			}
			pub, err := curve25519.X25519(priv, curve25519.Basepoint)
			if err != nil {
				errs[i] = err
				return
			}
			pubPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pub)
			signPub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				errs[i] = err
				return
			}
			signPubPEM := pem.EncodeToMemory(&pem.Block{Type: "NEBULA ED25519 PUBLIC KEY", Bytes: signPub})

			body, _ := json.Marshal(map[string]string{
				"token":                  token,
				"public_key_pem":         string(pubPEM),
				"signing_public_key_pem": string(signPubPEM),
			})
			req, err := http.NewRequestWithContext(context.Background(),
				http.MethodPost, h.Server.URL+"/api/v1/enroll", bytes.NewReader(body))
			if err != nil {
				errs[i] = err
				return
			}
			req.Header.Set("Content-Type", "application/json")
			<-start // release barrier: maximize ConsumeToken overlap
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				errs[i] = err
				return
			}
			codes[i] = resp.StatusCode
			var out struct {
				CertificatePEM string `json:"certificate_pem"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&out)
			gotCert[i] = out.CertificatePEM != ""
			_ = resp.Body.Close()
		}(i)
	}
	close(start)
	wg.Wait()

	redeemed := 0
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("redeemer %d transport error: %v", i, errs[i])
		}
		if codes[i] == http.StatusOK && gotCert[i] {
			redeemed++
		}
	}
	if redeemed != 1 {
		t.Errorf("TOKEN_SINGLE_USE violated: %d/%d concurrent redemptions of one token returned 200+cert; want exactly 1", redeemed, n)
	}
}
