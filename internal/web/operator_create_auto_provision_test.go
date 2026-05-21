package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// TestAdminCreatesUser_AutoProvisions verifies that when an admin creates
// a user-role operator, the default CA is auto-provisioned.
func TestAdminCreatesUser_AutoProvisions(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)

	// Create admin session.
	adminCookie := mintSession(t, s, "alice-admin", "admin")

	// POST /ui/operators with role=user.
	form := url.Values{
		"username":         {"bob"},
		"display_name":     {"Bob"},
		"password":         {"SecurePass123!@#"},
		"password_confirm": {"SecurePass123!@#"},
		"role":             {"user"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()

	w.ServeHTTP(rec, req)

	// Expect 303 redirect.
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("handleOperatorCreate: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	// Get bob's ID from store.
	ctx := context.Background()
	bob, err := s.GetOperatorByUsername(ctx, "bob")
	if err != nil {
		t.Fatalf("GetOperatorByUsername(bob) = %v", err)
	}

	// Verify default CA was created.
	cas, err := s.ListCAsByOwner(ctx, bob.ID)
	if err != nil {
		t.Fatalf("ListCAsByOwner = %v", err)
	}
	if len(cas) != 1 {
		t.Fatalf("bob should have 1 CA, got %d", len(cas))
	}

	ca := cas[0]
	if ca.Name != "bob-default" {
		t.Errorf("CA name = %q, want bob-default", ca.Name)
	}
	if ca.Status != models.CAStatusActive {
		t.Errorf("CA status = %q, want %q", ca.Status, models.CAStatusActive)
	}
	if ca.Fingerprint == "" {
		t.Error("CA fingerprint is empty")
	}
	if ca.OwnerOperatorID != bob.ID {
		t.Errorf("CA owner = %q, want %q", ca.OwnerOperatorID, bob.ID)
	}
}

// TestAdminCreatesAdmin_AutoProvisions verifies that when an admin
// creates an admin-role operator, a default CA is auto-provisioned.
func TestAdminCreatesAdmin_AutoProvisions(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)

	// Create admin session.
	adminCookie := mintSession(t, s, "alice-admin", "admin")

	// POST /ui/operators with role=admin.
	form := url.Values{
		"username":         {"charlie"},
		"display_name":     {"Charlie"},
		"password":         {"SecurePass123!@#"},
		"password_confirm": {"SecurePass123!@#"},
		"role":             {"admin"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()

	w.ServeHTTP(rec, req)

	// Expect 303 redirect.
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("handleOperatorCreate: status = %d, want 303", rec.Code)
	}

	// Get charlie's ID from store.
	ctx := context.Background()
	charlie, err := s.GetOperatorByUsername(ctx, "charlie")
	if err != nil {
		t.Fatalf("GetOperatorByUsername(charlie) = %v", err)
	}

	// Verify CA was created.
	cas, err := s.ListCAsByOwner(ctx, charlie.ID)
	if err != nil {
		t.Fatalf("ListCAsByOwner = %v", err)
	}
	if len(cas) != 1 {
		t.Fatalf("charlie should have 1 CA, got %d", len(cas))
	}

	ca := cas[0]
	if ca.Name != "charlie-default" {
		t.Errorf("CA name = %q, want charlie-default", ca.Name)
	}
	if ca.Status != models.CAStatusActive {
		t.Errorf("CA status = %q, want %q", ca.Status, models.CAStatusActive)
	}
	if ca.Fingerprint == "" {
		t.Error("CA fingerprint is empty")
	}
	if ca.OwnerOperatorID != charlie.ID {
		t.Errorf("CA owner = %q, want %q", ca.OwnerOperatorID, charlie.ID)
	}
}

// TestAdminCreatesUser_SkipsAutoProvisionWhenNoMaster verifies that when
// the master key is not configured, operator creation succeeds without
// auto-provisioning the CA.
func TestAdminCreatesUser_SkipsAutoProvisionWhenNoMaster(t *testing.T) {
	// Create Web WITHOUT master key.
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	w, err := New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Do NOT call WithMaster.

	// Create admin session.
	adminCookie := mintSession(t, s, "delta-admin", "admin")

	// POST /ui/operators with role=user.
	form := url.Values{
		"username":         {"eve"},
		"display_name":     {"Eve"},
		"password":         {"SecurePass123!@#"},
		"password_confirm": {"SecurePass123!@#"},
		"role":             {"user"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/ui/operators", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(adminCookie)
	rec := httptest.NewRecorder()

	w.ServeHTTP(rec, req)

	// Expect 303 redirect (NOT 500 — graceful failure).
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("handleOperatorCreate: status = %d, want 303 (graceful skip when no master); body=%s",
			rec.Code, rec.Body.String())
	}

	// Get eve's ID from store.
	ctx := context.Background()
	eve, err := s.GetOperatorByUsername(ctx, "eve")
	if err != nil {
		t.Fatalf("GetOperatorByUsername(eve) = %v", err)
	}

	// Verify no CA was created.
	cas, err := s.ListCAsByOwner(ctx, eve.ID)
	if err != nil {
		t.Fatalf("ListCAsByOwner = %v", err)
	}
	if len(cas) != 0 {
		t.Fatalf("eve should have 0 CAs (master not configured), got %d", len(cas))
	}
}
