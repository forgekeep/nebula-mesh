package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// extractTokenDisplay pulls the one-shot raw enrollment token out of the
// host-detail page rendered after POST /ui/hosts.
func extractTokenDisplay(t *testing.T, body string) string {
	t.Helper()
	const marker = `<div class="token-display">`
	start := strings.Index(body, marker)
	if start < 0 {
		t.Fatal("token-display not found in host-detail response")
	}
	start += len(marker)
	end := strings.Index(body[start:], "</div>")
	if end < 0 {
		t.Fatal("token-display closing tag not found")
	}
	return strings.TrimSpace(body[start : start+end])
}

func createHostViaUI(t *testing.T, w *Web, cookies []*http.Cookie, networkID, name string) string {
	t.Helper()
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
	form := url.Values{
		"network_id": {networkID},
		"name":       {name},
		"nebula_ips": {"10.0.0.5"},
		"role":       {"host"},
		"_csrf":      {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /ui/hosts status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}
	return extractTokenDisplay(t, rec.Body.String())
}

// TestUIHostCreate_HonorsNetworkEnrollmentTokenTTL is the GHSA-g4x6-jcvr-9m3g
// regression: a per-network enrollment_token_ttl override must bound the token
// minted by the Web UI host-creation path. Before the fix the handler hardcoded
// 24h and ignored the configured 30m override.
func TestUIHostCreate_HonorsNetworkEnrollmentTokenTTL(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "prod", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetNetworkConfig(ctx, "net1", "enrollment_token_ttl", "30m"); err != nil {
		t.Fatal(err)
	}

	before := time.Now()
	rawToken := createHostViaUI(t, w, cookies, "net1", "ttl-host")

	tok, err := s.GetEnrollmentToken(ctx, rawToken)
	if err != nil {
		t.Fatalf("GetEnrollmentToken: %v", err)
	}
	// Expiry must land inside the 30m override window, not at the old 24h.
	maxExpiry := time.Now().Add(30 * time.Minute).Add(time.Minute)
	if tok.ExpiresAt.After(maxExpiry) {
		t.Fatalf("token expiry %s exceeds configured 30m TTL (max %s); per-network override ignored",
			tok.ExpiresAt.Format(time.RFC3339), maxExpiry.Format(time.RFC3339))
	}
	if tok.ExpiresAt.Before(before.Add(25 * time.Minute)) {
		t.Fatalf("token expiry %s is shorter than the configured 30m TTL", tok.ExpiresAt.Format(time.RFC3339))
	}
}

// TestUIHostCreate_HonorsServerDefaultTTL covers the server-default path used
// when no per-network override is set.
func TestUIHostCreate_HonorsServerDefaultTTL(t *testing.T) {
	w, s := newTestWeb(t)
	w.WithEnrollmentTokenTTL(2 * time.Hour)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{ID: "net1", Name: "prod", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	rawToken := createHostViaUI(t, w, cookies, "net1", "default-ttl-host")

	tok, err := s.GetEnrollmentToken(ctx, rawToken)
	if err != nil {
		t.Fatalf("GetEnrollmentToken: %v", err)
	}
	maxExpiry := time.Now().Add(2 * time.Hour).Add(time.Minute)
	if tok.ExpiresAt.After(maxExpiry) {
		t.Fatalf("token expiry %s exceeds server-default 2h TTL", tok.ExpiresAt.Format(time.RFC3339))
	}
}
