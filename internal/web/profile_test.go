package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProfilePage_RequiresLogin(t *testing.T) {
	w, _ := newTestWeb(t)
	req := httptest.NewRequest(http.MethodGet, "/ui/profile", nil)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303", rec.Code)
	}
}

func TestProfilePage_ShowsOperatorDetailsAndLogoutButton(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)
	req := httptest.NewRequest(http.MethodGet, "/ui/profile", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, testUsername) {
		t.Error("profile page should display the username")
	}
	if !strings.Contains(body, `href="/ui/logout"`) {
		t.Error("profile page should expose the logout link")
	}
}

func TestDashboard_HasProfileChipAndNoLogoutInSidebar(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `href="/ui/profile"`) {
		t.Error("sidebar should contain a profile link")
	}
	// Top-level navigation no longer hosts Logout — it lives on /ui/profile now.
	if strings.Contains(body, `<a href="/ui/logout">Logout</a>`) {
		t.Error("sidebar should not contain Logout as a peer nav item anymore")
	}
}
