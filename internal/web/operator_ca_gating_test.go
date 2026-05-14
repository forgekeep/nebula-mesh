package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// seedActiveCA inserts a minimally-populated active CA owned by the given
// operator. Used in #93 gating tests where the precise key material is
// irrelevant — only the ownership/status check matters.
func seedActiveCA(t *testing.T, s store.Store, id, ownerID, name string) *models.CA {
	t.Helper()
	ca := &models.CA{
		ID:                   id,
		Name:                 name,
		OwnerOperatorID:      ownerID,
		Fingerprint:          "fp-" + id,
		NotBefore:            time.Now(),
		NotAfter:             time.Now().Add(time.Hour),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      []byte("d"),
		NonceDEK:             []byte("nd"),
		EncryptedKeyMaterial: []byte("k"),
		NonceKey:             []byte("nk"),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := s.CreateCA(context.Background(), ca); err != nil {
		t.Fatal(err)
	}
	return ca
}

// TestNetworkCreate_RejectsUserWithoutCA — issue #93. A self-registered
// (role=user) operator with zero active CAs must not be able to create
// a network. Re-render the networks page with an inline CTA pointing at
// /ui/cas/new.
func TestNetworkCreate_RejectsUserWithoutCA(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")

	form := url.Values{"name": {"alice-net"}, "cidrs": {"10.0.0.0/24"}}
	req := httptest.NewRequest("POST", "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/ui/cas/new") {
		t.Errorf("body should link to /ui/cas/new, got:\n%s", body)
	}
	if !strings.Contains(body, "Create a CA") {
		t.Errorf("body should explain the operator needs a CA, got:\n%s", body)
	}

	// And no network row was created in the store.
	nets, err := s.ListNetworks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 0 {
		t.Errorf("network should not have been created, got %d", len(nets))
	}
}

// TestNetworkCreate_UserWithSingleCA — when the user owns exactly one
// active CA, the network create handler must accept the form without an
// explicit ca_id and persist the CA's id on the network.
func TestNetworkCreate_UserWithSingleCA(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	ca := seedActiveCA(t, s, "ca-alice", "op-alice", "alice-ca")

	form := url.Values{"name": {"alice-net"}, "cidrs": {"10.0.0.0/24"}}
	req := httptest.NewRequest("POST", "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body: %s", rec.Code, rec.Body.String())
	}
	nets, err := s.ListNetworks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nets) != 1 {
		t.Fatalf("got %d networks, want 1", len(nets))
	}
	if nets[0].CAID != ca.ID {
		t.Errorf("network CAID = %q, want %q", nets[0].CAID, ca.ID)
	}
}

// TestNetworkCreate_UserMustPickWhenMultipleCAs — operators with more
// than one CA must explicitly pick one; otherwise the form re-renders
// with the "pick a CA" message.
func TestNetworkCreate_UserMustPickWhenMultipleCAs(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	seedActiveCA(t, s, "ca-1", "op-alice", "ca-one")
	seedActiveCA(t, s, "ca-2", "op-alice", "ca-two")

	form := url.Values{"name": {"alice-net"}, "cidrs": {"10.0.0.0/24"}}
	req := httptest.NewRequest("POST", "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "pick a CA") {
		t.Errorf("body should ask the operator to pick a CA")
	}
}

// TestNetworkCreate_UserCannotPickForeignCA — a user must not be able to
// submit another operator's CA id.
func TestNetworkCreate_UserCannotPickForeignCA(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	mintSession(t, s, "bob", "user") // FK target
	seedActiveCA(t, s, "ca-alice", "op-alice", "alice-ca")
	seedActiveCA(t, s, "ca-bob", "op-bob", "bob-ca")

	form := url.Values{"name": {"alice-net"}, "cidrs": {"10.0.0.0/24"}, "ca_id": {"ca-bob"}}
	req := httptest.NewRequest("POST", "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not accessible") {
		t.Errorf("body should reject the foreign CA")
	}
}

// TestHostCreate_UserCannotCreateInForeignNetwork — even if the user
// guesses the right network id, the host create handler must refuse a
// network whose CA they do not own (issue #93). The check survives the
// inline-error re-render added by #91.
func TestHostCreate_UserCannotCreateInForeignNetwork(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	mintSession(t, s, "bob", "user")
	bobCA := seedActiveCA(t, s, "ca-bob", "op-bob", "bob-ca")
	bobNet := &models.Network{ID: "n-bob", Name: "bob-net", CIDRs: []string{"10.10.0.0/24"}, CAID: bobCA.ID, CreatedAt: time.Now()}
	if err := s.CreateNetwork(context.Background(), bobNet); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id": {bobNet.ID},
		"name":       {"sneaky-host"},
		"nebula_ips":  {"10.10.0.10"},
		"role":       {"host"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "not tied to a CA you own") {
		t.Errorf("body should explain ownership rejection")
	}
	// And nothing was persisted.
	hosts, err := s.ListHosts(context.Background(), store.HostFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 0 {
		t.Errorf("host must not be persisted; got %d", len(hosts))
	}
}

// TestHostCreate_UserOwnedNetworkInheritsCAID — happy path. A user with
// their own CA + network creates a host; the host row inherits the
// network's CAID so the agent's cert is signed under that CA, not a
// fallback / seed CA.
func TestHostCreate_UserOwnedNetworkInheritsCAID(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	ca := seedActiveCA(t, s, "ca-alice", "op-alice", "alice-ca")
	net := &models.Network{ID: "n-alice", Name: "alice-net", CIDRs: []string{"10.20.0.0/24"}, CAID: ca.ID, CreatedAt: time.Now()}
	if err := s.CreateNetwork(context.Background(), net); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id": {net.ID},
		"name":       {"alice-host"},
		"nebula_ips":  {"10.20.0.5"},
		"role":       {"host"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	hosts, err := s.ListHosts(context.Background(), store.HostFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 {
		t.Fatalf("got %d hosts, want 1", len(hosts))
	}
	if hosts[0].CAID != ca.ID {
		t.Errorf("host CAID = %q, want %q (inherited from network)", hosts[0].CAID, ca.ID)
	}
}

// TestHostNew_UserWithoutAccessibleNetworks — a user with no networks
// (no CA → no networks) hitting /ui/hosts/new sees the "no accessible
// networks" alert instead of a broken form.
func TestHostNew_UserWithoutAccessibleNetworks(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")

	req := httptest.NewRequest("GET", "/ui/hosts/new", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No accessible networks") {
		t.Errorf("body should alert about missing networks; got:\n%s", body)
	}
	// And the form must not be there.
	if strings.Contains(body, `name="nebula_ips"`) {
		t.Errorf("form must be hidden when no networks are accessible")
	}
}
