package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juev/nebula-mesh/internal/ratelimit"
	"github.com/juev/nebula-mesh/internal/store"
)

func newRateLimitWeb(t *testing.T) *Web {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	w, err := New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestRateLimit_BlocksAfterBurst(t *testing.T) {
	w := newRateLimitWeb(t)
	w.WithRateLimiter(ratelimit.New(ratelimit.Config{
		Enabled: true,
		Groups:  map[string]ratelimit.GroupConfig{"auth": {Rate: 1, Burst: 2}},
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader("username=x&password=y"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.1.1.1:1234"
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d should be admitted within burst, got 429", i)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader("username=x&password=y"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "10.1.1.1:1234"
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("3rd POST: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on 429")
	}
}

func TestRateLimit_Disabled_PassesAll(t *testing.T) {
	w := newRateLimitWeb(t)
	w.WithRateLimiter(ratelimit.New(ratelimit.Config{Enabled: false}))

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader("username=x&password=y"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "10.1.1.1:1234"
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d should not be limited when disabled", i)
		}
	}
}

func TestRateLimit_AuditEntryOnBlock(t *testing.T) {
	w := newRateLimitWeb(t)
	w.WithRateLimiter(ratelimit.New(ratelimit.Config{
		Enabled: true,
		Groups:  map[string]ratelimit.GroupConfig{"auth": {Rate: 1, Burst: 1}},
	}))

	// Burn the burst.
	r1 := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader("u=a&p=b"))
	r1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r1.RemoteAddr = "203.0.113.42:1000"
	w.ServeHTTP(httptest.NewRecorder(), r1)

	// 2nd is rate-limited.
	r2 := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader("u=a&p=b"))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r2.RemoteAddr = "203.0.113.42:1000"
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, r2)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	entries, err := w.store.ListAuditEntries(context.Background(), store.AuditFilter{Action: "auth.rate_limited", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries: got %d, want 1", len(entries))
	}
	if entries[0].Resource != "203.0.113.0/24" {
		t.Errorf("resource = %q, want masked /24", entries[0].Resource)
	}
}

func TestRateLimit_HealthEndpointsExempt(t *testing.T) {
	w := newRateLimitWeb(t)
	w.WithRateLimiter(ratelimit.New(ratelimit.Config{
		Enabled: true,
		Groups: map[string]ratelimit.GroupConfig{
			"auth": {Rate: 0.1, Burst: 1},
			"ui":   {Rate: 0.1, Burst: 1},
		},
	}))

	// The Web mux does not own /healthz, but the limiter is wired to
	// auth/ui groups only — verify a /static/* request never trips the
	// limiter even when hammered.
	for i := 0; i < 30; i++ {
		req := httptest.NewRequest(http.MethodGet, "/static/htmx.min.js", nil)
		req.RemoteAddr = "203.0.113.99:1000"
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: /static/* must not be rate-limited", i)
		}
	}
}
