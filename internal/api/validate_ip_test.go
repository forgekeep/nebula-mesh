package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/juev/nebula-mesh/internal/models"
)

func TestCreateHost_FriendlyNebulaIPError(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "garbage", NebulaIPs: []string{"10.42.0.22.333"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	got := w.Body.String()
	if strings.Contains(got, "ParseAddr") {
		t.Errorf("response must not leak the stdlib ParseAddr text; got %s", got)
	}
	if !strings.Contains(got, "10.42.0.22.333") || !strings.Contains(got, "not a valid IPv4 or IPv6 address") {
		t.Errorf("response should identify the bad value and constraint; got %s", got)
	}
}

func TestCreateHost_FriendlyPublicIPError(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "lh", NebulaIPs: []string{"192.168.100.10"},
		Role: "lighthouse", PublicIP: "203.0.113.999", ListenPort: 4242,
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	got := w.Body.String()
	if strings.Contains(got, "ParseAddr") {
		t.Errorf("response must not leak the stdlib ParseAddr text; got %s", got)
	}
	if !strings.Contains(got, "public_ip") || !strings.Contains(got, "203.0.113.999") {
		t.Errorf("response should mention the field and bad value; got %s", got)
	}
}

func TestCreateNetwork_FriendlyCIDRError(t *testing.T) {
	srv, _ := newTestServer(t)
	body := []byte(`{"name":"n","cidrs":["not-a-cidr"]}`)
	req := httptest.NewRequest("POST", "/api/v1/networks", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	got := w.Body.String()
	if strings.Contains(got, "ParsePrefix") {
		t.Errorf("response must not leak the stdlib ParsePrefix text; got %s", got)
	}
	if !strings.Contains(got, "not a valid CIDR") {
		t.Errorf("response should explain the constraint; got %s", got)
	}
}

func TestCreateHost_FriendlyAdvancedListenHostError(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "adv", NebulaIPs: []string{"192.168.100.20"},
		Advanced: &models.HostAdvanced{ListenHost: "not-an-ip"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	got := w.Body.String()
	if strings.Contains(got, "ParseAddr") {
		t.Errorf("response must not leak the stdlib ParseAddr text; got %s", got)
	}
	if !strings.Contains(got, "advanced.listen_host") {
		t.Errorf("response should mention the field; got %s", got)
	}
}

func TestCreateHost_FriendlyUnsafeRouteError(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "ur", NebulaIPs: []string{"192.168.100.21"},
		Advanced: &models.HostAdvanced{
			UnsafeRoutes: []models.UnsafeRoute{{Route: "bad/cidr", Via: "10.0.0.1"}},
		},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	got := w.Body.String()
	if strings.Contains(got, "ParsePrefix") || strings.Contains(got, "ParseAddr") {
		t.Errorf("response must not leak stdlib parse text; got %s", got)
	}
	if !strings.Contains(got, "unsafe_routes[0].route") {
		t.Errorf("response should mention the indexed field; got %s", got)
	}
}

func TestCreateHost_RejectsIPOutsideCIDR(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv) // helper creates 192.168.100.0/24

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID, Name: "wrong-net", NebulaIPs: []string{"10.0.0.1"},
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
		NetworkID: netID, Name: "h1", NebulaIPs: []string{"192.168.100.10"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create = %d", w.Code)
	}

	body, _ = json.Marshal(createHostRequest{
		NetworkID: netID, Name: "h2", NebulaIPs: []string{"192.168.100.10"},
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
		NetworkID: netID, Name: "net-addr", NebulaIPs: []string{"192.168.100.0"},
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
		NetworkID: netID, Name: "broadcast", NebulaIPs: []string{"192.168.100.255"},
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
		ID: "net-other", Name: "other", CIDRs: []string{"10.20.0.0/24"},
	}); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(createHostRequest{
		NetworkID: net1, Name: "h1", NebulaIPs: []string{"192.168.100.10"},
	})
	req := httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create = %d", w.Code)
	}

	body, _ = json.Marshal(createHostRequest{
		NetworkID: "net-other", Name: "h2", NebulaIPs: []string{"10.20.0.10"},
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
		NetworkID: netID, Name: "h1", NebulaIPs: []string{"192.168.100.10"},
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
		NetworkID: netID, Name: "h2", NebulaIPs: []string{"192.168.100.10"},
	})
	req = httptest.NewRequest("POST", "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("reuse-after-block status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
