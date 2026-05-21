package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSidebarNav_NoCAsLink — issue #102. The CAs link should be hidden
// from the main sidebar navigation for both user and admin roles.
// Users access their CAs through Profile; admins through Settings.
func TestSidebarNav_NoCAsLink_UserRole(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Extract sidebar-nav block
	startIdx := strings.Index(body, `<div class="sidebar-nav">`)
	if startIdx == -1 {
		t.Fatal("sidebar-nav block not found in HTML")
	}

	// Find the closing </div> after sidebar-nav
	navBlock := body[startIdx:]
	endIdx := strings.Index(navBlock, "</div>")
	if endIdx == -1 {
		t.Fatal("closing </div> for sidebar-nav not found")
	}

	navBlock = navBlock[:endIdx]

	// Check that href="/ui/cas" is NOT present in the sidebar-nav block
	if strings.Contains(navBlock, `href="/ui/cas"`) {
		t.Error("sidebar-nav should not contain href=\"/ui/cas\" for user role")
	}
}

// TestSidebarNav_NoCAsLink_AdminRole — issue #102. Admin should also not
// see CAs link in main sidebar navigation (admins access via Settings).
func TestSidebarNav_NoCAsLink_AdminRole(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "bob", "admin")

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Extract sidebar-nav block
	startIdx := strings.Index(body, `<div class="sidebar-nav">`)
	if startIdx == -1 {
		t.Fatal("sidebar-nav block not found in HTML")
	}

	// Find the closing </div> after sidebar-nav
	navBlock := body[startIdx:]
	endIdx := strings.Index(navBlock, "</div>")
	if endIdx == -1 {
		t.Fatal("closing </div> for sidebar-nav not found")
	}

	navBlock = navBlock[:endIdx]

	// Check that href="/ui/cas" is NOT present in the sidebar-nav block
	if strings.Contains(navBlock, `href="/ui/cas"`) {
		t.Error("sidebar-nav should not contain href=\"/ui/cas\" for admin role")
	}
}
