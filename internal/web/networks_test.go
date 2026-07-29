package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestHandleCreateNetwork_AdminWithoutCA_RejectsEmptyCAID verifies that
// an admin operator without selecting a CA is rejected when creating a network.
// This enforces SEC-PERSIST-001: the admin should not be allowed to persist an
// empty ca_id (the legacy fallthrough path).
func TestHandleCreateNetwork_AdminWithoutCA_RejectsEmptyCAID(t *testing.T) {
	w, s := newOperatorsWeb(t)
	adminCookie := mintSession(t, s, "admin", "admin")

	// Get CSRF token from the networks page
	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/networks", []*http.Cookie{adminCookie})

	// Form submission without ca_id selected
	form := url.Values{}
	form.Set("name", "test-net")
	form["cidrs"] = []string{"10.0.0.0/24"}
	form.Set("_csrf", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rw := httptest.NewRecorder()
	w.ServeHTTP(rw, req)

	// Must reject with error
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rw.Code)
	}
	body := rw.Body.String()
	if !strings.Contains(body, "pick a CA") && !strings.Contains(body, "must create a CA") {
		t.Errorf("response should mention CA selection requirement, got: %s", body)
	}

	// Verify no network was persisted with empty ca_id
	networks, err := s.ListNetworks(context.Background())
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	for _, net := range networks {
		if net.Name == "test-net" && net.CAID == "" {
			t.Error("network was persisted with empty CAID, violates SEC-PERSIST-001")
		}
	}
}

// TestHandleCreateNetwork_NonAdminWithoutCA_Rejects is a sanity check that
// non-admin operators without CAs are also rejected (existing behavior).
func TestHandleCreateNetwork_NonAdminWithoutCA_Rejects(t *testing.T) {
	w, s := newOperatorsWeb(t)
	userCookie := mintSession(t, s, "user", "user")

	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/networks", []*http.Cookie{userCookie})

	form := url.Values{}
	form.Set("name", "test-net")
	form.Add("cidr", "10.0.0.0/24")
	form.Set("_csrf", csrfToken)

	req := httptest.NewRequest(http.MethodPost, "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rw := httptest.NewRecorder()
	w.ServeHTTP(rw, req)

	if rw.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rw.Code)
	}
}

// TestHandleCreateNetwork_AdminWithCA_Succeeds verifies that an admin who
// explicitly selects a CA can create a network (existing behavior preserved).
func TestHandleCreateNetwork_AdminWithCA_Succeeds(t *testing.T) {
	w, s := newOperatorsWeb(t)
	adminCookie := mintSession(t, s, "admin", "admin")

	// Create a CA for the admin to select
	ca := &models.CA{
		ID:                   uuid.New().String(),
		Name:                 "test-ca",
		OwnerOperatorID:      "op-admin",
		CertPEM:              "-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
		Fingerprint:          "fp-test",
		NotBefore:            time.Now(),
		NotAfter:             time.Now().Add(time.Hour),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      []byte("dek"),
		NonceDEK:             []byte("ndek"),
		EncryptedKeyMaterial: []byte("key"),
		NonceKey:             []byte("nkey"),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatalf("create CA: %v", err)
	}

	csrfToken, cookies := getCSRFTokenFromCookies(t, w, "/ui/networks", []*http.Cookie{adminCookie})

	// Form submission with explicit ca_id
	form := url.Values{
		"name":  {"test-net"},
		"cidrs": {"10.0.0.0/24"},
		"ca_id": {ca.ID},
		"_csrf": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rw := httptest.NewRecorder()
	w.ServeHTTP(rw, req)

	// Verify network was created with the selected CA
	networks, err := s.ListNetworks(context.Background())
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}

	var found *models.Network
	for _, net := range networks {
		if net.Name == "test-net" {
			found = net
			break
		}
	}
	if found == nil {
		t.Fatal("network was not created")
	}
	if found.CAID != ca.ID {
		t.Errorf("network CAID = %q, want %q", found.CAID, ca.ID)
	}
}
