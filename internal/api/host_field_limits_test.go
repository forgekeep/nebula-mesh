package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #186: host Name and Groups are embedded in the signed cert and distributed
// mesh-wide, so they must be length- and count-bounded at the API.

func createHostStatus(t *testing.T, srv *Server, req createHostRequest) int {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(r)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w.Code
}

func TestCreateHost_RejectsOversizedName(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	code := createHostStatus(t, srv, createHostRequest{
		NetworkID: netID,
		Name:      strings.Repeat("a", maxHostNameLen+1),
		NebulaIPs: []string{"192.168.100.10"},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("oversized name: status = %d, want 400", code)
	}
}

func TestCreateHost_RejectsTooManyGroups(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	groups := make([]string, maxHostGroups+1)
	for i := range groups {
		groups[i] = "g"
	}
	code := createHostStatus(t, srv, createHostRequest{
		NetworkID: netID,
		Name:      "many-groups",
		NebulaIPs: []string{"192.168.100.11"},
		Groups:    groups,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("too many groups: status = %d, want 400", code)
	}
}

func TestCreateHost_RejectsOversizedGroupName(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	code := createHostStatus(t, srv, createHostRequest{
		NetworkID: netID,
		Name:      "long-group",
		NebulaIPs: []string{"192.168.100.12"},
		Groups:    []string{strings.Repeat("g", maxGroupNameLen+1)},
	})
	if code != http.StatusBadRequest {
		t.Fatalf("oversized group name: status = %d, want 400", code)
	}
}

func TestCreateHost_AllowsAtLimits(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	groups := make([]string, maxHostGroups)
	for i := range groups {
		groups[i] = strings.Repeat("g", maxGroupNameLen)
	}
	code := createHostStatus(t, srv, createHostRequest{
		NetworkID: netID,
		Name:      strings.Repeat("a", maxHostNameLen),
		NebulaIPs: []string{"192.168.100.13"},
		Groups:    groups,
	})
	if code != http.StatusCreated {
		t.Fatalf("at-limit values: status = %d, want 201", code)
	}
}
