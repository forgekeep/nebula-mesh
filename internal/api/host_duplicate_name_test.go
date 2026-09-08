package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postHost submits a host-create request and returns the recorder.
func postHost(t *testing.T, srv *Server, networkID, name, ip string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(createHostRequest{
		NetworkID: networkID,
		Name:      name,
		NebulaIPs: []string{ip},
		Role:      "host",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts", bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// TestCreateHost_DuplicateNameConflicts pins the API side of the same gap the
// web form had: the handler already maps the overlay-address collision to 409
// (ErrIPTaken) but let the UNIQUE(network_id, name) violation fall through to
// a 500, reporting an operator input error as a server fault.
func TestCreateHost_DuplicateNameConflicts(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	if w := postHost(t, srv, netID, "blai", "192.168.100.10"); w.Code != http.StatusCreated {
		t.Fatalf("first create: status = %d, want 201; body=%s", w.Code, w.Body.String())
	}

	w := postHost(t, srv, netID, "blai", "192.168.100.11")
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate name: status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "blai") || !strings.Contains(body, "already exists") {
		t.Errorf("error should name the colliding host and say it already exists; got: %s", body)
	}
}

// TestCreateHost_SameNameDifferentNetworkAllowed keeps the 409 scoped to the
// network the constraint actually covers.
func TestCreateHost_SameNameDifferentNetworkAllowed(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	body := `{"name":"second-net","cidrs":["192.168.200.0/24"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/networks", bytes.NewBufferString(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	var second struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&second); err != nil {
		t.Fatal(err)
	}

	if rec := postHost(t, srv, netID, "shared", "192.168.100.20"); rec.Code != http.StatusCreated {
		t.Fatalf("create in first network: status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if rec := postHost(t, srv, second.ID, "shared", "192.168.200.20"); rec.Code != http.StatusCreated {
		t.Errorf("same name in another network must succeed: status = %d; body=%s", rec.Code, rec.Body.String())
	}
}

// patchHostName submits a rename and returns the recorder.
func patchHostName(t *testing.T, srv *Server, hostID, name string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(updateHostRequest{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+hostID, bytes.NewBuffer(body))
	authRequest(req)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// TestUpdateHost_DuplicateNameRejected covers the rename half of the gap. The
// handler already answers 409 for a colliding overlay address; a colliding
// name is the same class of operator error and trips the same table's unique
// index, so it must not surface as a 500.
func TestUpdateHost_DuplicateNameRejected(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	createHostHelper(t, srv, netID, "tauro", "192.168.100.30", nil)
	mover := createHostHelper(t, srv, netID, "agricer", "192.168.100.31", nil)

	w := patchHostName(t, srv, mover.ID, "tauro")
	if w.Code != http.StatusConflict {
		t.Fatalf("rename onto a taken name: status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "tauro") || !strings.Contains(body, "already exists") {
		t.Errorf("error should name the colliding host and say it already exists; got: %s", body)
	}
}

// TestUpdateHost_RenameToOwnNameAllowed guards the self-exclusion: resubmitting
// a host's existing name is not a conflict.
func TestUpdateHost_RenameToOwnNameAllowed(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)

	host := createHostHelper(t, srv, netID, "isis", "192.168.100.40", nil)

	if w := patchHostName(t, srv, host.ID, "isis"); w.Code != http.StatusOK {
		t.Errorf("keeping its own name: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}
