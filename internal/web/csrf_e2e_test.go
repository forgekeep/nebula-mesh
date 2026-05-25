package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestCSRF_E2E_CADeleteHappy tests the happy path: CA deletion with valid CSRF token.
func TestCSRF_E2E_CADeleteHappy(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "bob", "user")

	// Create a CA owned by bob via the store directly
	now := time.Now()
	ca := &models.CA{
		ID:                   "ca-delete-happy",
		Name:                 "ca-to-delete",
		OwnerOperatorID:      "op-bob",
		CertPEM:              "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:          "fp-delete",
		NotBefore:            now,
		NotAfter:             now.Add(time.Hour),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      []byte("dek"),
		NonceDEK:             []byte("ndek"),
		EncryptedKeyMaterial: []byte("key"),
		NonceKey:             []byte("nkey"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}

	// Get CSRF token from a GET request to /ui/cas/{id}
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/cas/"+ca.ID, []*http.Cookie{cookie})

	// POST /ui/cas/{id}/delete with valid CSRF token
	req := httptest.NewRequest(http.MethodPost, "/ui/cas/"+ca.ID+"/delete", strings.NewReader("_csrf="+csrfToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	// Expect redirect (303)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete with valid CSRF: status = %d, want 303", rec.Code)
	}

	// Verify redirect location is /ui/cas
	location := rec.Header().Get("Location")
	if location != "/ui/cas" {
		t.Errorf("delete redirect: got %q, want /ui/cas", location)
	}

	// Verify CA is deleted from the store
	_, err := s.GetCA(context.Background(), ca.ID)
	if err == nil {
		t.Fatal("CA should be deleted, but GetCA returned no error")
	}
	// The error should be ErrNotFound or similar (implementation-specific)
	// Just verify it's not a success
}

// TestCSRF_E2E_CADeleteRejected tests CSRF rejection: CA deletion without token fails.
func TestCSRF_E2E_CADeleteRejected(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")

	// Create a CA owned by alice via the store directly
	now := time.Now()
	ca := &models.CA{
		ID:                   "ca-delete-rejected",
		Name:                 "ca-not-deleted",
		OwnerOperatorID:      "op-alice",
		CertPEM:              "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:          "fp-reject",
		NotBefore:            now,
		NotAfter:             now.Add(time.Hour),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      []byte("dek"),
		NonceDEK:             []byte("ndek"),
		EncryptedKeyMaterial: []byte("key"),
		NonceKey:             []byte("nkey"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}

	// POST /ui/cas/{id}/delete WITHOUT CSRF token (but with session cookie)
	// Empty body, no _csrf field or X-CSRF-Token header
	req := httptest.NewRequest(http.MethodPost, "/ui/cas/"+ca.ID+"/delete", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	// Expect 403 Forbidden
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete without CSRF: status = %d, want 403", rec.Code)
	}

	// Verify CA still exists in the store
	got, err := s.GetCA(context.Background(), ca.ID)
	if err != nil {
		t.Fatalf("CA should still exist, but GetCA failed: %v", err)
	}
	if got.ID != ca.ID {
		t.Errorf("CA ID mismatch: got %q, want %q", got.ID, ca.ID)
	}

	// Verify audit entry was recorded with action "web.csrf.rejected"
	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, entry := range entries {
		if entry.Action == "web.csrf.rejected" && strings.Contains(entry.Resource, "/ui/cas/"+ca.ID+"/delete") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected audit entry with action=web.csrf.rejected not found")
	}
}
