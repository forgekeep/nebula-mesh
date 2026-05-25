package api

import (
	"bytes"
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
