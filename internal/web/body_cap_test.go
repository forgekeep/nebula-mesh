package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMaxBodySize_RejectsOversizedUIPost verifies the #185 cap: an
// unauthenticated /ui POST whose body exceeds the limit is rejected with 413
// before any form parsing reads it into memory.
func TestMaxBodySize_RejectsOversizedUIPost(t *testing.T) {
	web, _ := newTestWeb(t)
	big := strings.Repeat("a", (1<<20)+1024) // > 1 MiB cap

	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	web.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized /ui/login POST: status = %d, want 413", rec.Code)
	}
}

// TestMaxBodySize_AllowsNormalUIPost guards against the cap rejecting normal
// form submissions (it must only fire on oversized bodies).
func TestMaxBodySize_AllowsNormalUIPost(t *testing.T) {
	web, _ := newTestWeb(t)

	req := httptest.NewRequest(http.MethodPost, "/ui/login", strings.NewReader("username=x&password=y"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	web.ServeHTTP(rec, req)

	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("normal /ui/login POST wrongly rejected as too large (413)")
	}
}
