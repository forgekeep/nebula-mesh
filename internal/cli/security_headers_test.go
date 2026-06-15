package cli

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_PlainHTTP(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	h.ServeHTTP(rec, req)

	got := rec.Result().Header

	wantPrefix := map[string]string{
		"Content-Security-Policy": "default-src 'self';",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "same-origin",
		"X-Frame-Options":         "DENY",
	}
	for k, prefix := range wantPrefix {
		v := got.Get(k)
		if v == "" {
			t.Errorf("%s missing", k)
			continue
		}
		if !strings.HasPrefix(v, prefix) {
			t.Errorf("%s = %q, want prefix %q", k, v, prefix)
		}
	}

	// HSTS must NOT be set on plain HTTP — sending it from a plain
	// listener would invite the client to upgrade to a non-listening
	// HTTPS endpoint.
	if v := got.Get("Strict-Transport-Security"); v != "" {
		t.Errorf("HSTS set on plain HTTP: %q", v)
	}
}

func TestSecurityHeaders_TLS_SetsHSTS(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	req.TLS = &tls.ConnectionState{}
	h.ServeHTTP(rec, req)

	hsts := rec.Result().Header.Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatal("HSTS missing on TLS request")
	}
	if !strings.Contains(hsts, "max-age=") {
		t.Errorf("HSTS without max-age: %q", hsts)
	}
	if !strings.Contains(hsts, "includeSubDomains") {
		t.Errorf("HSTS without includeSubDomains: %q", hsts)
	}
}

func TestSecurityHeaders_CSPDirectives(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := securityHeaders(inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	csp := rec.Result().Header.Get("Content-Security-Policy")
	want := []string{
		"default-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action 'self'",
	}
	for _, d := range want {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP missing %q; got %q", d, csp)
		}
	}
}

func TestSecurityHeaders_AppliedOnErrorResponse(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	h := securityHeaders(inner)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if rec.Result().Header.Get("X-Frame-Options") != "DENY" {
		t.Error("security headers stripped on error response")
	}
}
