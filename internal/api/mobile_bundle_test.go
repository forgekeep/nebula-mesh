package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
	"gopkg.in/yaml.v3"
)

// TestHandleMobileBundle_Success verifies the handler generates a mobile bundle
// for a mobile host and returns YAML with proper content-type header.
func TestHandleMobileBundle_Success(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)

	// Create a mobile host
	now := time.Now()
	host := &models.Host{
		ID:        uuid.New().String(),
		NetworkID: netID,
		Name:      "iphone-1",
		NebulaIPs: []string{"192.168.100.50"},
		Kind:      models.HostKindMobile,
		Variant:   models.HostVariantIOS,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      srv.defaultCAID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.CreateHost(context.Background(), host); err != nil {
		t.Fatalf("create mobile host: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/hosts/"+host.ID+"/mobile-bundle", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", w.Code, w.Body.String())
	}

	// Check content-type header
	if ct := w.Header().Get("Content-Type"); ct != "application/yaml; charset=utf-8" {
		t.Errorf("Content-Type = %q, want 'application/yaml; charset=utf-8'", ct)
	}

	// Verify body is valid YAML with expected keys
	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(w.Body.Bytes(), &yamlData); err != nil {
		t.Fatalf("parse YAML response: %v", err)
	}
	if _, ok := yamlData["pki"]; !ok {
		t.Error("YAML missing 'pki' key")
	}

	// Verify host status was updated to enrolled
	updated, err := st.GetHost(context.Background(), host.ID)
	if err != nil {
		t.Fatalf("get host after bundle: %v", err)
	}
	if updated.Status != models.HostStatusEnrolled {
		t.Errorf("host status = %q, want %q", updated.Status, models.HostStatusEnrolled)
	}
}

// TestHandleMobileBundle_RejectsNonMobile verifies non-mobile hosts get 400.
func TestHandleMobileBundle_RejectsNonMobile(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)

	// Create an agent (non-mobile) host
	now := time.Now()
	host := &models.Host{
		ID:        uuid.New().String(),
		NetworkID: netID,
		Name:      "agent-1",
		NebulaIPs: []string{"192.168.100.51"},
		Kind:      models.HostKindAgent,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CAID:      srv.defaultCAID,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := st.CreateHost(context.Background(), host); err != nil {
		t.Fatalf("create agent host: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/hosts/"+host.ID+"/mobile-bundle", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp["error"] == "" {
		t.Error("error response missing error message")
	}
}

// TestHandleMobileBundle_NotFound verifies missing host returns 404.
func TestHandleMobileBundle_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("POST", "/api/v1/hosts/nonexistent/mobile-bundle", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// TestHandleMobileBundle_Unauthorized verifies missing bearer auth returns 401.
func TestHandleMobileBundle_Unauthorized(t *testing.T) {
	srv, _ := newTestServer(t)

	req := httptest.NewRequest("POST", "/api/v1/hosts/anything/mobile-bundle", nil)
	// Note: no authRequest call — missing Authorization header
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
