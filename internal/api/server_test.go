package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

const testAPIKey = "test-api-key-12345"

func newTestServer(t *testing.T) (*Server, *store.SQLiteStore) {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	ca, _, err := pki.NewCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	logger := slog.Default()
	srv := NewServer(s, ca, testAPIKey, logger)
	return srv, s
}

func authRequest(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
}

// --- Health ---

func TestHealth(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want ok", resp["status"])
	}
}

// --- Auth Middleware ---

func TestAuthMiddleware_NoHeader(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_InvalidKey(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer wrong-key")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_ValidKey(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/hosts", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// --- Networks ---

func TestCreateAndListNetworks(t *testing.T) {
	srv, _ := newTestServer(t)

	body := `{"name":"test-net","cidr":"192.168.100.0/24"}`
	req := httptest.NewRequest("POST", "/api/v1/networks", bytes.NewBufferString(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var created models.Network
	json.NewDecoder(w.Body).Decode(&created)
	if created.Name != "test-net" {
		t.Errorf("name = %q, want test-net", created.Name)
	}

	// List
	req = httptest.NewRequest("GET", "/api/v1/networks", nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", w.Code, http.StatusOK)
	}

	var networks []models.Network
	json.NewDecoder(w.Body).Decode(&networks)
	if len(networks) != 1 {
		t.Errorf("len = %d, want 1", len(networks))
	}
}

// --- Hosts ---

func createNetwork(t *testing.T, srv *Server) string {
	t.Helper()
	body := `{"name":"test-net","cidr":"192.168.100.0/24"}`
	req := httptest.NewRequest("POST", "/api/v1/networks", bytes.NewBufferString(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var net models.Network
	json.NewDecoder(w.Body).Decode(&net)
	return net.ID
}

func TestCreateAndGetHost(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "web-1",
		NebulaIP:  "192.168.100.10",
		Groups:    []string{"web"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}

	var resp createHostResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Host.Name != "web-1" {
		t.Errorf("name = %q, want web-1", resp.Host.Name)
	}
	if resp.EnrollmentToken == "" {
		t.Error("enrollment token is empty")
	}

	// Get host
	req = httptest.NewRequest("GET", "/api/v1/hosts/"+resp.Host.ID, nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("get status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestDeleteHost(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "to-delete", NebulaIP: "192.168.100.20",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	var resp createHostResponse
	json.NewDecoder(w.Body).Decode(&resp)

	req = httptest.NewRequest("DELETE", "/api/v1/hosts/"+resp.Host.ID, nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("delete status = %d, want %d", w.Code, http.StatusNoContent)
	}

	// Verify deleted
	req = httptest.NewRequest("GET", "/api/v1/hosts/"+resp.Host.ID, nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("get after delete status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHostNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest("GET", "/api/v1/hosts/nonexistent", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}
