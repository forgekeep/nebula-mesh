package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"

	"github.com/forgekeep/nebula-mesh/internal/ratelimit"
)

func TestOIDC_LoginRoute_RateLimited(t *testing.T) {
	w := newRateLimitWeb(t)
	w.WithRateLimiter(ratelimit.New(ratelimit.Config{
		Enabled: true,
		Groups:  map[string]ratelimit.GroupConfig{"auth": {Rate: 0.001, Burst: 2}},
	}))
	flowCipher, err := newOIDCFlowCipher()
	if err != nil {
		t.Fatal(err)
	}
	o := &OIDC{
		flowCipher: flowCipher,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		oauth: &oauth2.Config{
			ClientID:    "cid",
			RedirectURL: "https://nebula-mesh.test/ui/oidc/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.test/authorize"},
		},
	}
	w.WithOIDC(o)

	const ip = "10.2.2.2:9999"
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ui/oidc/login", nil)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d should be admitted within burst, got 429", i)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/ui/oidc/login", nil)
	req.RemoteAddr = ip
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("third GET /ui/oidc/login status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
}
