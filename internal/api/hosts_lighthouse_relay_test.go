package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// TestCreateHost_LighthouseRelay covers the combined role: a host created
// with role=lighthouse+relay must carry both IsLighthouse and IsRelay so it
// is advertised to peers as a lighthouse (lighthouse.hosts/static_host_map)
// and as a relay (relay.relays) at the same time.
func TestCreateHost_LighthouseRelay(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID:  netID,
		Name:       "lh-relay",
		NebulaIPs:  []string{"192.168.100.20"},
		Role:       "lighthouse+relay",
		PublicIP:   "203.0.113.20",
		ListenPort: 4242,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	var resp createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Host.Role != models.HostRoleLighthouseRelay {
		t.Errorf("role = %q, want %q", resp.Host.Role, models.HostRoleLighthouseRelay)
	}
	if !resp.Host.IsLighthouse {
		t.Error("IsLighthouse = false, want true")
	}
	if !resp.Host.IsRelay {
		t.Error("IsRelay = false, want true")
	}
}

// TestCreateHost_LighthouseRelay_RequiresReachability: the combined role
// inherits the same guard as lighthouse/relay — without public_ip and
// listen_port the host would never be dialed by peers.
func TestCreateHost_LighthouseRelay_RequiresReachability(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	cases := []struct {
		name       string
		publicIP   string
		listenPort int
		nebulaIP   string
		wantSubstr string
	}{
		{"missing public_ip", "", 4242, "192.168.100.21", "public_ip"},
		{"missing listen_port", "203.0.113.21", 0, "192.168.100.22", "listen_port"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(createHostRequest{
				NetworkID:  netID,
				Name:       "lh-relay-bad",
				NebulaIPs:  []string{tc.nebulaIP},
				Role:       "lighthouse+relay",
				PublicIP:   tc.publicIP,
				ListenPort: tc.listenPort,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
			authRequest(req)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d, body: %s", w.Code, http.StatusBadRequest, w.Body.String())
			}
			if !bytes.Contains(w.Body.Bytes(), []byte(tc.wantSubstr)) {
				t.Errorf("body = %q, want substring %q", w.Body.String(), tc.wantSubstr)
			}
		})
	}
}

// TestUpdateHost_LighthouseRelay: PATCHing role to lighthouse+relay must
// re-derive both booleans, and PATCHing away must clear them.
func TestUpdateHost_LighthouseRelay(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID:  netID,
		Name:       "patch-me",
		NebulaIPs:  []string{"192.168.100.23"},
		Role:       "host",
		PublicIP:   "203.0.113.23",
		ListenPort: 4242,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create host: %d %s", w.Code, w.Body.String())
	}
	var created createHostResponse
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}

	patch := func(role string) *models.Host {
		t.Helper()
		patchBody, _ := json.Marshal(updateHostRequest{Role: &role})
		patchReq := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+created.Host.ID, bytes.NewBuffer(patchBody))
		authRequest(patchReq)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, patchReq)
		if rec.Code != http.StatusOK {
			t.Fatalf("patch role=%s: %d %s", role, rec.Code, rec.Body.String())
		}
		var updated models.Host
		if err := json.NewDecoder(rec.Body).Decode(&updated); err != nil {
			t.Fatalf("decode patch response: %v", err)
		}
		return &updated
	}

	updated := patch("lighthouse+relay")
	if !updated.IsLighthouse || !updated.IsRelay {
		t.Errorf("after patch to lighthouse+relay: IsLighthouse=%v IsRelay=%v, want true/true",
			updated.IsLighthouse, updated.IsRelay)
	}

	reverted := patch("host")
	if reverted.IsLighthouse || reverted.IsRelay {
		t.Errorf("after patch back to host: IsLighthouse=%v IsRelay=%v, want false/false",
			reverted.IsLighthouse, reverted.IsRelay)
	}
}
