package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestCreateNetwork_AcceptsCIDRs(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"name":  "dual-stack-net",
		"cidrs": []string{"10.0.0.0/24", "fd00::/64"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body: %s", w.Code, w.Body.String())
	}

	var net models.Network
	if err := json.NewDecoder(w.Body).Decode(&net); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(net.CIDRs) != 2 {
		t.Errorf("expected 2 CIDRs, got %d", len(net.CIDRs))
	}
	if net.CIDRs[0] != "10.0.0.0/24" {
		t.Errorf("CIDRs[0] = %q, want '10.0.0.0/24'", net.CIDRs[0])
	}
	if net.CIDRs[1] != "fd00::/64" {
		t.Errorf("CIDRs[1] = %q, want 'fd00::/64'", net.CIDRs[1])
	}
}

func TestCreateNetwork_RejectsSingularCIDR(t *testing.T) {
	srv, _ := newTestServer(t)

	body := `{"name":"test-net","cidr":"10.0.0.0/24"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBufferString(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}

	errMsg := errResp["error"]
	if errMsg == "" {
		t.Fatal("error message is empty")
	}
	// Should mention the old field and suggest the new one
	if !bytes.Contains([]byte(errMsg), []byte("cidr")) {
		t.Errorf("error message should mention 'cidr', got: %s", errMsg)
	}
	if !bytes.Contains([]byte(errMsg), []byte("cidrs")) {
		t.Errorf("error message should mention 'cidrs', got: %s", errMsg)
	}
}

func TestCreateNetwork_EmptyCIDRs(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"name":  "empty-net",
		"cidrs": []string{},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty CIDRs, got %d, body: %s", w.Code, w.Body.String())
	}
}

func TestCreateNetwork_RejectsOverlappingCIDRs(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"name":  "overlap-net",
		"cidrs": []string{"10.0.0.0/16", "10.0.0.0/24"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for overlapping CIDRs, got %d, body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "overlap") {
		t.Errorf("expected overlap message, got: %s", w.Body.String())
	}
}

func TestCreateNetwork_RejectsDuplicateCIDRs(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"name":  "dup-net",
		"cidrs": []string{"10.0.0.0/24", "10.0.0.0/24"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate CIDRs, got %d, body: %s", w.Code, w.Body.String())
	}
}

// TestCreateNetwork_SEC_PERSIST_001_OmittingCAIDResolvesDefaultAndPersistsNonEmpty
// enforces SEC-PERSIST-001: creating a network without ca_id must resolve the
// server default CA and persist a non-empty ca_id. The startup invariant
// CountEmptyCAIDRows (serve.go:134-140) must remain zero after creation.
func TestCreateNetwork_SEC_PERSIST_001_OmittingCAIDResolvesDefaultAndPersistsNonEmpty(t *testing.T) {
	srv, s := newTestServer(t)
	ctx := context.Background()

	// Get the default CA ID that newTestServer configured
	defaultCAID := srv.defaultCAID
	if defaultCAID == "" {
		t.Fatal("newTestServer did not set defaultCAID")
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":  "test-net",
		"cidrs": []string{"10.0.0.0/24"},
		// Note: no ca_id field submitted
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body: %s", w.Code, w.Body.String())
	}

	var net models.Network
	if err := json.NewDecoder(w.Body).Decode(&net); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// CAID must be resolved to the default CA, not empty
	if net.CAID != defaultCAID {
		t.Errorf("CAID = %q, want defaultCAID %q (empty CAID would break startup invariant)", net.CAID, defaultCAID)
	}

	// Startup invariant CountEmptyCAIDRows must be zero
	empty, err := s.CountEmptyCAIDRows(ctx)
	if err != nil {
		t.Fatalf("CountEmptyCAIDRows: %v", err)
	}
	if empty != 0 {
		t.Errorf("CountEmptyCAIDRows = %d, want 0 (startup invariant would reject server restart)", empty)
	}
}

// TestCreateNetwork_NoDefaultCA_RejectsEmptyCAID verifies that omitting ca_id
// when the server has no default CA configured returns 400 and does not persist
// a network. This ensures the reject path works correctly.
func TestCreateNetwork_NoDefaultCA_RejectsEmptyCAID(t *testing.T) {
	srv, s := newTestServer(t)
	ctx := context.Background()

	// Clear the default CA to simulate a server without one configured
	srv.defaultCAID = ""

	body, _ := json.Marshal(map[string]interface{}{
		"name":  "test-net",
		"cidrs": []string{"10.0.0.0/24"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", w.Code, w.Body.String())
	}

	// Verify the error message mentions the requirement
	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp["error"] == "" {
		t.Fatal("error message is empty")
	}

	// Verify no network was persisted (CountEmptyCAIDRows should still be 0)
	empty, err := s.CountEmptyCAIDRows(ctx)
	if err != nil {
		t.Fatalf("CountEmptyCAIDRows: %v", err)
	}
	if empty != 0 {
		t.Errorf("CountEmptyCAIDRows = %d, want 0 (network should not have been persisted)", empty)
	}
}
