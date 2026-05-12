package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juev/nebula-mesh/internal/models"
)

func TestCreateHost_RejectsIPOutsideCIDR(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv) // helper creates 192.168.100.0/24

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "wrong-net", NebulaIP: "10.0.0.1",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestCreateHost_RejectsDuplicateIPInSameNetwork(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "h1", NebulaIP: "192.168.100.10",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create = %d", w.Code)
	}

	body, _ = json.Marshal(createHostRequest{
		NetworkID: netID, Name: "h2", NebulaIP: "192.168.100.10",
	})
	req = httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("duplicate IP status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestCreateHost_RejectsIPv4NetworkAddress(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "net-addr", NebulaIP: "192.168.100.0",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCreateHost_RejectsIPv4BroadcastAddress(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "broadcast", NebulaIP: "192.168.100.255",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestCreateHost_AllowsDuplicateIPAcrossDifferentNetworks(t *testing.T) {
	srv, st := newTestServer(t)
	net1 := createNetwork(t, srv)

	// Second network with a different name/CIDR
	if err := st.CreateNetwork(context.Background(), &models.Network{
		ID: "net-other", Name: "other", CIDR: "10.20.0.0/24",
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(createHostRequest{
		NetworkID: net1, Name: "h1", NebulaIP: "192.168.100.10",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create = %d", w.Code)
	}

	body, _ = json.Marshal(createHostRequest{
		NetworkID: "net-other", Name: "h2", NebulaIP: "10.20.0.10",
	})
	req = httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("different-network create = %d; body=%s", w.Code, w.Body.String())
	}
}

func TestValidateHostIP_BlockedHostStillHoldsItsAddress(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "h1", NebulaIP: "192.168.100.10",
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create = %d", w.Code)
	}
	var resp createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	if _, err := st.BlockHostAndAddToBlocklist(context.Background(), resp.Host.ID, "for test"); err != nil {
		t.Fatal(err)
	}

	// Re-using the same IP must still be rejected: blocked hosts hold their
	// slot to preserve audit history. Operators delete the host explicitly
	// to free the address.
	body, _ = json.Marshal(createHostRequest{
		NetworkID: netID, Name: "h2", NebulaIP: "192.168.100.10",
	})
	req = httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("reuse-after-block status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
