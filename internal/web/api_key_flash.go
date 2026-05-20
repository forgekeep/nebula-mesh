package web

import (
	"net/http"
	"time"
)

// setAPIKeyFlash stashes a freshly-minted API key for one-shot reveal on
// the operator-detail page that follows the post-redirect-get. The flash
// is keyed by the requestor's session cookie so a refresh from a
// different browser (or after the TTL) sees nothing.
//
// Closes GHSA-9pg3-25fq-p6cc: previously the raw token was appended to
// the redirect Location header as a query string, ending up in browser
// history, the Referer header on cross-origin asset loads, and any
// proxy / CDN / load-balancer access log on the path.
func (w *Web) setAPIKeyFlash(r *http.Request, raw, name string) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return
	}
	w.apiKeyFlashMu.Lock()
	defer w.apiKeyFlashMu.Unlock()
	if w.apiKeyFlash == nil {
		w.apiKeyFlash = make(map[string]apiKeyFlashEntry)
	}
	// Opportunistic eviction so abandoned flashes (set but never popped)
	// don't leak memory. Set is rare (admin clicks "create key") so the
	// O(n) sweep is cheap.
	now := time.Now()
	for k, v := range w.apiKeyFlash {
		if now.After(v.Expiry) {
			delete(w.apiKeyFlash, k)
		}
	}
	w.apiKeyFlash[c.Value] = apiKeyFlashEntry{
		Key:     raw,
		KeyName: name,
		Expiry:  now.Add(apiKeyFlashTTL),
	}
}

// popAPIKeyFlash returns the raw API key and its label set by the most
// recent createAPIKey on this session, consuming it so a refresh never
// shows the same secret twice. Empty strings + ok=false on miss/expiry.
func (w *Web) popAPIKeyFlash(r *http.Request) (raw, name string, ok bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return "", "", false
	}
	w.apiKeyFlashMu.Lock()
	defer w.apiKeyFlashMu.Unlock()
	f, ok := w.apiKeyFlash[c.Value]
	if !ok {
		return "", "", false
	}
	delete(w.apiKeyFlash, c.Value)
	if time.Now().After(f.Expiry) {
		return "", "", false
	}
	return f.Key, f.KeyName, true
}
