package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestReenroll_MintsTokenAndPreservesHost(t *testing.T) {
	srv, st := newTestServer(t)
	netID := createNetwork(t, srv)

	body, _ := json.Marshal(createHostRequest{
		NetworkID: netID,
		Name:      "reenroll-host",
		NebulaIPs: []string{"192.168.100.42"},
		Groups:    []string{"g1"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create host: %d", w.Code)
	}
	var initial createHostResponse
	_ = json.NewDecoder(w.Body).Decode(&initial)

	// Force the host into enrolled state so we can confirm the row
	// survives across reenroll.
	if err := st.UpdateHostStatus(context.Background(), initial.Host.ID, models.HostStatusEnrolled); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+initial.Host.ID+"/reenroll", nil)
	authRequest(req)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("reenroll: status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp regenerateEnrollmentTokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" || resp.Token == initial.EnrollmentToken {
		t.Errorf("reenroll token must be fresh; got %q", resp.Token)
	}

	// Host row survives — ID, IP, groups, status unchanged.
	got, err := st.GetHost(context.Background(), initial.Host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != initial.Host.ID || len(got.NebulaIPs) != len(initial.Host.NebulaIPs) {
		t.Errorf("host row mutated; got %+v", got)
	}
	for i := range got.NebulaIPs {
		if got.NebulaIPs[i] != initial.Host.NebulaIPs[i] {
			t.Errorf("nebula IPs changed; got %+v", got.NebulaIPs)
			break
		}
	}
	if len(got.Groups) != 1 || got.Groups[0] != "g1" {
		t.Errorf("groups changed; got %v", got.Groups)
	}
}

func TestReenroll_HostNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/missing/reenroll", nil)
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestReenroll_RequiresAuth(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/anything/reenroll", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}
