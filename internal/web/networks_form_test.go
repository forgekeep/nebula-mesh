package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNetworksForm_HidesSelectorWhenSingleCA — issue #101. When a user
// owns exactly one active CA, the GET /ui/networks form must render a
// hidden input, not a <select>, and display "Signed by CA:" label.
func TestNetworksForm_HidesSelectorWhenSingleCA(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	ca := seedActiveCA(t, s, "ca-alice", "op-alice", "alice-ca")

	req := httptest.NewRequest("GET", "/ui/networks", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Should NOT contain the <select name="ca_id"
	if strings.Contains(body, `<select name="ca_id"`) {
		t.Error("HTML should not contain <select name=\"ca_id\" when user has exactly 1 CA")
	}

	// Should contain the "Signed by CA:" label
	if !strings.Contains(body, "Signed by CA") {
		t.Error("HTML should contain 'Signed by CA' label when user has exactly 1 CA")
	}

	// Should contain hidden input with the CA id
	if !strings.Contains(body, `value="`+ca.ID+`"`) {
		t.Errorf("HTML should contain hidden input with ca id %q", ca.ID)
	}
}

// TestNetworksForm_ShowsSelectorWhenMultipleCAs — issue #101. When a user
// owns more than one active CA, the GET /ui/networks form must render a
// <select> dropdown with all CA options and placeholder text.
func TestNetworksForm_ShowsSelectorWhenMultipleCAs(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	ca1 := seedActiveCA(t, s, "ca-1", "op-alice", "ca-one")
	ca2 := seedActiveCA(t, s, "ca-2", "op-alice", "ca-two")

	req := httptest.NewRequest("GET", "/ui/networks", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := rec.Body.String()

	// Should contain the <select name="ca_id"
	if !strings.Contains(body, `<select name="ca_id"`) {
		t.Error("HTML should contain <select name=\"ca_id\" when user has >1 CA")
	}

	// Should contain placeholder option
	if !strings.Contains(body, "Select CA...") {
		t.Error("HTML should contain placeholder 'Select CA...' option")
	}

	// Should contain both CA options
	if !strings.Contains(body, `value="`+ca1.ID+`"`) {
		t.Errorf("HTML should contain option with ca1 id %q", ca1.ID)
	}
	if !strings.Contains(body, `value="`+ca2.ID+`"`) {
		t.Errorf("HTML should contain option with ca2 id %q", ca2.ID)
	}
}
