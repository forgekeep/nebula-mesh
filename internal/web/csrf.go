// Package web includes CSRF protection for /ui/* mutating endpoints.
//
// Mechanism: stateless double-submit cookie. A non-HttpOnly cookie carries a
// 32-byte crypto/rand token. Every mutating request (POST/PUT/PATCH/DELETE)
// must echo the same token either in the X-CSRF-Token header (used by htmx)
// or in the _csrf form field (used by HTML forms). Comparison is
// constant-time.
//
// Cookie rotation happens on every privilege transition (Login, OIDC
// StartAuthenticatedSession, CompleteTwoFactor, Logout) — see session.go.
//
// Known limitations:
//   - A compromised same-registrable-domain origin (sibling subdomain
//     takeover) can set parent-domain cookies and forge a match.
//     SameSite=Lax does not prevent this. This is an inherent limitation
//     of stateless double-submit; mitigations would require server-side
//     token storage and are out of scope for this fix.
//   - The middleware calls r.ParseForm() for non-GET requests so the
//     _csrf form field can be read. This is safe for application/x-www-
//     form-urlencoded bodies (Go caches the parsed form). For future
//     multipart/JSON endpoints under /ui/*, the X-CSRF-Token header
//     path is the only supported mechanism — extend accordingly.
//   - HttpOnly is intentionally false on _csrf cookie: the layout script
//     reads it from document.cookie / meta tag to inject into htmx
//     hx-headers. This means an XSS bug degrades CSRF protection to
//     XSS-level. Content-Security-Policy headers (see GHSA-w7w5 fix)
//     mitigate the XSS surface.
package web

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"net/http"
)

const csrfCookieName = "nebula_csrf"
const csrfHeaderName = "X-CSRF-Token"
const csrfFormField = "_csrf"

// csrfContextKey is used to store the CSRF token in request context.
type csrfContextKey struct{}

// csrfMiddleware validates CSRF tokens on mutating requests (POST/PUT/PATCH/DELETE)
// and ensures a CSRF cookie exists on all requests.
func (w *Web) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		// For GET/HEAD/OPTIONS, ensure cookie exists and skip validation
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			cookieToken := getCookie(r, csrfCookieName)
			if cookieToken == "" {
				// Generate new token from the session manager's entropy
				// source so production and tests share one injection point.
				token, err := generateCSRFToken(w.session.csrfRand)
				if err != nil {
					http.Error(rw, "Internal server error", http.StatusInternalServerError)
					return
				}
				setCSRFCookie(rw, token, w.session.cookieSecure)
				cookieToken = token
			}
			// Store token in context for template rendering
			r = r.WithContext(context.WithValue(r.Context(), csrfContextKey{}, cookieToken))
			next.ServeHTTP(rw, r)
			return
		}

		// For mutating requests, validate CSRF token
		cookieToken := getCookie(r, csrfCookieName)
		if cookieToken == "" {
			w.rejectCSRF(rw, r, "missing_cookie")
			return
		}

		// Try to read token from header first (for htmx)
		bodyToken := r.Header.Get(csrfHeaderName)

		// If not in header, try form field
		if bodyToken == "" {
			err := r.ParseForm()
			if err != nil {
				http.Error(rw, "Bad Request", http.StatusBadRequest)
				return
			}
			bodyToken = r.PostForm.Get(csrfFormField)
		}

		if bodyToken == "" {
			w.rejectCSRF(rw, r, "missing_token")
			return
		}

		// Constant-time comparison
		if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(bodyToken)) != 1 {
			w.rejectCSRF(rw, r, "mismatch")
			return
		}

		// Token valid — store in context for template rendering
		r = r.WithContext(context.WithValue(r.Context(), csrfContextKey{}, cookieToken))
		next.ServeHTTP(rw, r)
	})
}

// rejectCSRF logs a CSRF rejection and returns 403 Forbidden.
func (w *Web) rejectCSRF(rw http.ResponseWriter, r *http.Request, reason string) {
	actor := "anonymous"
	if op := w.session.CurrentOperator(r); op != nil {
		actor = op.Username
	}

	resource := r.URL.Path
	// Audit log the rejection
	ctx := r.Context()
	_ = w.store.AddAuditEntry(ctx, actor, "web.csrf.rejected", resource, reason)

	rw.WriteHeader(http.StatusForbidden)
	fmt.Fprint(rw, "forbidden\n")
}

// getCookie retrieves a cookie value from the request.
func getCookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// setCSRFCookie sets a CSRF token cookie with appropriate attributes.
func setCSRFCookie(rw http.ResponseWriter, token string, secure bool) {
	http.SetCookie(rw, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // Must be readable by JS for htmx
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearCSRFCookie deletes a CSRF token cookie (RFC 6265 style).
func clearCSRFCookie(rw http.ResponseWriter, secure bool) {
	http.SetCookie(rw, &http.Cookie{
		Name:     csrfCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1, // Delete cookie
	})
}

// tokenFromContext extracts the CSRF token from request context.
func tokenFromContext(ctx context.Context) string {
	token, ok := ctx.Value(csrfContextKey{}).(string)
	if !ok {
		return ""
	}
	return token
}

// csrfFieldHTML returns an HTML hidden input field for CSRF protection.
func csrfFieldHTML(token string) template.HTML {
	// Escape the token to prevent injection
	escaped := template.HTMLEscapeString(token)
	// #nosec G203 -- token is already escaped via template.HTMLEscapeString
	// above; wrapping in template.HTML is the standard Go pattern for
	// returning trusted HTML from a FuncMap closure.
	//nolint:gocritic // %s is correct here — HTMLEscapeString already
	// escaped " and other HTML-special chars; %q would inject Go-quoting
	// (\" backslashes) which is not valid HTML.
	return template.HTML(fmt.Sprintf(`<input type="hidden" name="_csrf" value="%s">`, escaped))
}

// generateCSRFToken generates a new 32-byte CSRF token (hex-encoded) from
// the given entropy source. Production callers pass rand.Reader; tests
// pass a failing reader via SessionManager.csrfRand to exercise the
// fail-closed rotation paths in session.go (see csrf_failclosed_test.go).
func generateCSRFToken(r io.Reader) (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
