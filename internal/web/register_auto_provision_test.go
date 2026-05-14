package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSelfRegister_AutoProvisionsDefaultCA(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	w.AllowSelfRegistration(true)

	form := url.Values{
		"username":         {"alice"},
		"password":         {strongPassword},
		"password_confirm": {strongPassword},
	}
	req := httptest.NewRequest("POST", "/ui/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("register status = %d, want 303", rec.Code)
	}

	// Verify operator was created.
	ctx := context.Background()
	op, err := s.GetOperatorByUsername(ctx, "alice")
	if err != nil {
		t.Fatalf("operator not found: %v", err)
	}

	// Verify default CA was auto-provisioned.
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Fatalf("ListCAsByOwner returned %d CA(s), want 1", len(cas))
	}

	ca := cas[0]
	if ca.Name != "alice-default" {
		t.Errorf("CA name = %q, want alice-default", ca.Name)
	}
	if ca.OwnerOperatorID != op.ID {
		t.Errorf("CA owner = %q, want %q", ca.OwnerOperatorID, op.ID)
	}
	if ca.Status != "active" {
		t.Errorf("CA status = %q, want active", ca.Status)
	}
	if ca.Fingerprint == "" {
		t.Error("CA fingerprint is empty")
	}
}

func TestSelfRegister_SkipsAutoProvisionWhenNoMaster(t *testing.T) {
	// Create Web without master key (newTestWeb does not call WithMaster).
	w, s := newTestWeb(t)
	w.AllowSelfRegistration(true)

	form := url.Values{
		"username":         {"bob"},
		"password":         {strongPassword},
		"password_confirm": {strongPassword},
	}
	req := httptest.NewRequest("POST", "/ui/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("register status = %d, want 303", rec.Code)
	}

	// Verify operator was created.
	ctx := context.Background()
	op, err := s.GetOperatorByUsername(ctx, "bob")
	if err != nil {
		t.Fatalf("operator lookup error: %v", err)
	}

	// Verify no CA was created (since master is nil, provision is skipped).
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 0 {
		t.Fatalf("ListCAsByOwner returned %d CA(s), want 0 (provision should be skipped when no master)", len(cas))
	}
}
