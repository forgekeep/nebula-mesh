package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestLimiter_Disabled_AlwaysAllows(t *testing.T) {
	l := New(Config{Enabled: false})
	if l != nil {
		t.Fatal("New(Enabled=false) should return nil so middleware short-circuits")
	}
	allowed, _ := l.Allow("1.2.3.4", "auth")
	if !allowed {
		t.Error("nil limiter must allow")
	}
}

func TestLimiter_AuthGroup_Burst10(t *testing.T) {
	l := New(Config{
		Enabled: true,
		Groups: map[string]GroupConfig{
			"auth": {Rate: 5, Burst: 10},
		},
	})

	// Burst of 10 — first ten requests admit immediately.
	for i := 0; i < 10; i++ {
		if allowed, _ := l.Allow("10.0.0.1", "auth"); !allowed {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}

	allowed, retry := l.Allow("10.0.0.1", "auth")
	if allowed {
		t.Error("11th request should be rejected (burst exhausted)")
	}
	if retry <= 0 {
		t.Errorf("Retry-After = %v, want > 0", retry)
	}
}

func TestLimiter_PerIPIsolation(t *testing.T) {
	l := New(Config{
		Enabled: true,
		Groups:  map[string]GroupConfig{"auth": {Rate: 1, Burst: 1}},
	})

	if allowed, _ := l.Allow("10.0.0.1", "auth"); !allowed {
		t.Fatal("first request from .1 must be allowed")
	}
	if allowed, _ := l.Allow("10.0.0.1", "auth"); allowed {
		t.Fatal("second request from .1 must be denied")
	}
	if allowed, _ := l.Allow("10.0.0.2", "auth"); !allowed {
		t.Fatal("request from .2 must be allowed (different IP key)")
	}
}

func TestLimiter_UnknownGroupAllows(t *testing.T) {
	l := New(Config{Enabled: true, Groups: map[string]GroupConfig{"auth": {Rate: 1, Burst: 1}}})
	allowed, _ := l.Allow("1.2.3.4", "unknown")
	if !allowed {
		t.Error("unknown group should pass through")
	}
}

func TestClientIP_TrustProxyHeader(t *testing.T) {
	l := New(Config{
		Enabled:          true,
		TrustProxyHeader: true,
		Groups:           map[string]GroupConfig{"auth": {Rate: 5, Burst: 10}},
	})

	tests := []struct {
		name string
		xff  string
		want string
	}{
		{
			name: "single entry appended by proxy",
			xff:  "203.0.113.10",
			want: "203.0.113.10",
		},
		{
			// The proxy appends the connecting client's IP on the
			// right; anything to the left arrived in the client's own
			// header and must not be trusted.
			name: "rightmost wins over client-supplied entries",
			xff:  "198.51.100.99, 203.0.113.10",
			want: "203.0.113.10",
		},
		{
			// A client rotating a fake leftmost entry per request must
			// still key on the address the proxy saw.
			name: "spoofed leftmost entry ignored",
			xff:  "10.99.99.99, 203.0.113.10",
			want: "203.0.113.10",
		},
		{
			// No leftward fallback: an unparseable rightmost entry
			// must not let the client pick its own key from a left
			// entry — fall through to RemoteAddr instead.
			name: "unparseable rightmost falls back to RemoteAddr, not leftward",
			xff:  "198.51.100.99, not-an-ip",
			want: "127.0.0.1",
		},
		{
			name: "empty rightmost falls back to RemoteAddr",
			xff:  "198.51.100.99,",
			want: "127.0.0.1",
		},
		{
			name: "IPv6 rightmost",
			xff:  "198.51.100.99, 2001:db8::7",
			want: "2001:db8::7",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "127.0.0.1:5555"
			r.Header.Set("X-Forwarded-For", tc.xff)
			if got := l.ClientIP(r); got != tc.want {
				t.Errorf("ClientIP(xff=%q) = %q, want %q", tc.xff, got, tc.want)
			}
		})
	}
}

func TestClientIP_NoTrust_UsesRemoteAddr(t *testing.T) {
	l := New(Config{Enabled: true, Groups: map[string]GroupConfig{"auth": {Rate: 5, Burst: 10}}})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.5:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.10")
	if got := l.ClientIP(r); got != "192.0.2.5" {
		t.Errorf("ClientIP = %q, want 192.0.2.5 (X-Forwarded-For ignored)", got)
	}
}

func TestClientIP_UntrustedDirectPeerIgnoresForwardedHeader(t *testing.T) {
	l := New(Config{
		Enabled:          true,
		TrustProxyHeader: true,
		Groups:           map[string]GroupConfig{"auth": {Rate: 5, Burst: 10}},
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.5:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.10")
	if got := l.ClientIP(r); got != "192.0.2.5" {
		t.Errorf("ClientIP = %q, want direct peer 192.0.2.5", got)
	}
}

func TestClientIP_ConfiguredProxyUsesForwardedHeader(t *testing.T) {
	l := New(Config{
		Enabled:              true,
		TrustProxyHeader:     true,
		TrustedProxyPrefixes: []netip.Prefix{netip.MustParsePrefix("10.42.0.0/16")},
		Groups:               map[string]GroupConfig{"auth": {Rate: 5, Burst: 10}},
	})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.42.7.9:1234"
	r.Header.Set("X-Forwarded-For", "198.51.100.25")
	if got := l.ClientIP(r); got != "198.51.100.25" {
		t.Errorf("ClientIP = %q, want forwarded client 198.51.100.25", got)
	}
}

func TestClientIP_IPv6(t *testing.T) {
	l := New(Config{Enabled: true, Groups: map[string]GroupConfig{"auth": {Rate: 5, Burst: 10}}})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8::1]:5000"
	if got := l.ClientIP(r); got != "2001:db8::1" {
		t.Errorf("ClientIP = %q, want 2001:db8::1", got)
	}
}

func TestMaskIP(t *testing.T) {
	tests := map[string]string{
		"203.0.113.42":          "203.0.113.0/24",
		"10.0.0.1":              "10.0.0.0/24",
		"2001:db8:1234:5678::1": "2001:db8:1234:5678::/64",
		"not-an-ip":             "not-an-ip",
	}
	for in, want := range tests {
		if got := MaskIP(in); got != want {
			t.Errorf("MaskIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteRetryAfter_SetsHeaderAnd429(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteRetryAfter(rec, 3*time.Second)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("status = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "3" {
		t.Errorf("Retry-After = %q, want %q", got, "3")
	}
	if !strings.Contains(rec.Body.String(), "rate limit exceeded") {
		t.Errorf("body missing rate-limit message: %s", rec.Body.String())
	}
}
