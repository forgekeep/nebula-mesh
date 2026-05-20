package cli

import "net/http"

// securityHeaders wraps next with HTTP response security headers per advisory
// GHSA-w7w5-5gcp-38rw: clickjacking, MIME sniffing, referrer leakage, and
// (on TLS) protocol downgrade defenses.
//
// CSP keeps 'unsafe-inline' on script-src and style-src for compatibility
// with existing inline <script>, <style>, onclick=, and style="..." usage
// in templates. Tightening that requires extracting inline blocks and
// rewiring inline event handlers, tracked separately.
func securityHeaders(next http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self' 'unsafe-inline'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"frame-ancestors 'none'; " +
		"base-uri 'none'; " +
		"form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
