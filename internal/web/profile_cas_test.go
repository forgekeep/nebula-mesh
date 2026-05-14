package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProfile_ShowsMyCAs(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")

	ca1 := seedActiveCA(t, s, "ca-1", "op-alice", "ca-one")
	ca2 := seedActiveCA(t, s, "ca-2", "op-alice", "ca-two")

	req := httptest.NewRequest("GET", "/ui/profile", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Check for card heading
	if !strings.Contains(body, "My Certificate Authorities") {
		t.Error("profile page should display 'My Certificate Authorities' card")
	}

	// Check for CA names
	if !strings.Contains(body, ca1.Name) {
		t.Errorf("profile page should display CA name %q", ca1.Name)
	}
	if !strings.Contains(body, ca2.Name) {
		t.Errorf("profile page should display CA name %q", ca2.Name)
	}

	// Check for fingerprints
	if !strings.Contains(body, ca1.Fingerprint) {
		t.Errorf("profile page should display CA fingerprint %q", ca1.Fingerprint)
	}
	if !strings.Contains(body, ca2.Fingerprint) {
		t.Errorf("profile page should display CA fingerprint %q", ca2.Fingerprint)
	}

	// Check for detail links
	if !strings.Contains(body, "/ui/cas/"+ca1.ID) {
		t.Errorf("profile page should contain link to /ui/cas/%s", ca1.ID)
	}
	if !strings.Contains(body, "/ui/cas/"+ca2.ID) {
		t.Errorf("profile page should contain link to /ui/cas/%s", ca2.ID)
	}
}

func TestProfile_EmptyState(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")

	req := httptest.NewRequest("GET", "/ui/profile", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Check for card heading
	if !strings.Contains(body, "My Certificate Authorities") {
		t.Error("profile page should display 'My Certificate Authorities' card")
	}

	// Check for empty state message
	if !strings.Contains(body, "No certificate authorities yet") {
		t.Error("profile page should display empty state message")
	}

	// Check for create link
	if !strings.Contains(body, `href="/ui/cas/new"`) {
		t.Error("profile page should contain link to /ui/cas/new")
	}
}
