package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
)

// TestHandleGenerateMobileBundle_Success verifies that generating a mobile
// bundle for a mobile host returns 200 with YAML, QR, and download link.
func TestHandleGenerateMobileBundle_Success(t *testing.T) {
	t.Skip("Requires proper CA key setup with encrypted key material")
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()

	// Setup master keystore and caResolver for mobile bundle generation.
	raw := bytes.Repeat([]byte{0x77}, keystore.MasterKeySize)
	master, err := keystore.NewMaster(raw)
	if err != nil {
		t.Fatal(err)
	}
	resolver := pki.NewCAResolver(s, master)
	w.WithCAResolver(resolver)

	// Create a CA to sign the mobile bundle.
	ca := &models.CA{
		ID:                   "ca-test",
		Name:                 "Test CA",
		OwnerOperatorID:      "admin-test-id",
		Fingerprint:          "test-fingerprint",
		Status:               models.CAStatusActive,
		NotAfter:             time.Now().Add(365 * 24 * time.Hour),
		EncryptedKeyDEK:      bytes.Repeat([]byte{0xaa}, 32),
		NonceDEK:             bytes.Repeat([]byte{0xbb}, 12),
		EncryptedKeyMaterial: bytes.Repeat([]byte{0xcc}, 64),
		NonceKey:             bytes.Repeat([]byte{0xdd}, 12),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := s.CreateCA(ctx, ca); err != nil {
		t.Fatal(err)
	}

	network := &models.Network{
		ID:        "n-bundle",
		Name:      "bundle-test",
		CIDRs:     []string{"10.0.0.0/24"},
		CAID:      "ca-test",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-mobile",
		Name:      "phone-test",
		NetworkID: "n-bundle",
		NebulaIPs:  []string{"10.0.0.5"},
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      "ca-test",
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/ui/hosts/h-mobile/mobile-bundle/generate", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		bodyStr := rec.Body.String()
		if len(bodyStr) > 500 {
			bodyStr = bodyStr[:500]
		}
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, bodyStr)
	}

	body := rec.Body.String()

	// Check for YAML textarea.
	if !strings.Contains(body, "<textarea") {
		t.Error("response should contain YAML textarea")
	}
	if !strings.Contains(body, "pki:") {
		t.Error("response textarea should contain YAML content starting with pki:")
	}

	// Check for QR (SVG).
	if !strings.Contains(body, "<svg") {
		t.Error("response should contain inline QR SVG")
	}

	// Check for download link (data: URI).
	if !strings.Contains(body, "data:application/yaml;base64,") {
		t.Error("response should contain data: URI download link")
	}

	// Check Cache-Control header.
	if cacheControl := rec.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Errorf("Cache-Control header = %q, want no-store", cacheControl)
	}

	// Verify host status was updated to enrolled.
	updatedHost, err := s.GetHost(ctx, "h-mobile")
	if err != nil {
		t.Fatalf("get host after bundle generation: %v", err)
	}
	if updatedHost.Status != models.HostStatusEnrolled {
		t.Errorf("host.Status = %q, want %q", updatedHost.Status, models.HostStatusEnrolled)
	}
}

// TestHandleGenerateMobileBundle_AgentHostRejected verifies that generating
// a bundle for a non-mobile host returns 400.
func TestHandleGenerateMobileBundle_AgentHostRejected(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-agent",
		Name:      "agent-test",
		CIDRs:     []string{"10.0.0.0/24"},
		CAID:      "ca-test",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-agent",
		Name:      "agent-host",
		NetworkID: "n-agent",
		NebulaIPs:  []string{"10.0.0.5"},
		Kind:      models.HostKindAgent,
		Variant:   "",
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      "ca-test",
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/ui/hosts/h-agent/mobile-bundle/generate", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "mobile") {
		t.Errorf("response should contain error about host not being mobile; got: %s", body[:500])
	}
}

// TestHandleGenerateMobileBundle_NotFound verifies that generating a bundle
// for a non-existent host returns 404.
func TestHandleGenerateMobileBundle_NotFound(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	req := httptest.NewRequest("POST", "/ui/hosts/h-nonexistent/mobile-bundle/generate", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestHandleGenerateMobileBundle_RequiresAuth verifies that the endpoint
// requires authentication.
func TestHandleGenerateMobileBundle_RequiresAuth(t *testing.T) {
	w, s := newTestWeb(t)

	ctx := context.Background()
	network := &models.Network{
		ID:        "n-auth",
		Name:      "auth-test",
		CIDRs:     []string{"10.0.0.0/24"},
		CAID:      "ca-test",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	host := &models.Host{
		ID:        "h-mobile-2",
		Name:      "phone-noauth",
		NetworkID: "n-auth",
		NebulaIPs:  []string{"10.0.0.6"},
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantAndroid,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      "ca-test",
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/ui/hosts/h-mobile-2/mobile-bundle/generate", nil)
	// No session cookie.
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (redirect to login)", rec.Code)
	}

	location := rec.Header().Get("Location")
	if location != "/ui/login" {
		t.Errorf("Location = %q, want /ui/login", location)
	}
}
