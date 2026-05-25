package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// seedTenant creates a CA owned by opID, a network under it, and a host under
// it, so cross-tenant access can be exercised. suffix keeps ids/names unique
// and greppable in rendered HTML.
func seedTenant(t *testing.T, s store.Store, opID, suffix string) (caID, netID, hostID string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	caID = "ca-" + suffix
	if err := s.CreateCA(ctx, &models.CA{
		ID: caID, Name: caID, OwnerOperatorID: opID, Fingerprint: "fp-" + suffix,
		CertPEM: "stub", Status: models.CAStatusActive, NotBefore: now, NotAfter: now.Add(time.Hour),
		EncryptedKeyDEK: []byte("d"), NonceDEK: []byte("n"),
		EncryptedKeyMaterial: []byte("k"), NonceKey: []byte("nk"),
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateCA %s: %v", suffix, err)
	}
	netID = "net-" + suffix
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: netID, Name: "net-" + suffix, CIDRs: []string{"10.0.0.0/24"}, CAID: caID, CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateNetwork %s: %v", suffix, err)
	}
	hostID = "host-" + suffix
	if err := s.CreateHost(ctx, &models.Host{
		ID: hostID, NetworkID: netID, CAID: caID, Name: "host-" + suffix,
		Role: models.HostRoleHost, Status: models.HostStatusPending, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateHost %s: %v", suffix, err)
	}
	return caID, netID, hostID
}

// twoTenants sets up operator bob (whose session cookie is returned) and
// operator alice, each owning a CA/network/host. Returns bob's cookie and the
// two host ids (alice's = foreign to bob).
func twoTenants(t *testing.T, w *Web, s store.Store) (bob *http.Cookie, foreignHost, ownHost string) {
	t.Helper()
	bob = authedSession(t, s, "bob", "user")
	authedSession(t, s, "alice", "user")
	_, _, foreignHost = seedTenant(t, s, "op-alice", "a")
	_, _, ownHost = seedTenant(t, s, "op-bob", "b")
	return bob, foreignHost, ownHost
}

func TestWebHostDetail_NonOwnerForbidden(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob, foreignHost, ownHost := twoTenants(t, w, s)

	// bob sees his own host.
	if code := webGET(t, w, "/ui/hosts/"+ownHost, bob); code != http.StatusOK {
		t.Errorf("own host detail: status = %d, want 200", code)
	}
	// bob cannot see alice's host.
	if code := webGET(t, w, "/ui/hosts/"+foreignHost, bob); code != http.StatusForbidden {
		t.Errorf("foreign host detail: status = %d, want 403", code)
	}
}

func TestWebHosts_ListScopedToOwner(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob, _, _ := twoTenants(t, w, s)

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts", nil)
	req.AddCookie(bob)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("hosts list: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "host-b") {
		t.Error("bob should see his own host (host-b)")
	}
	if strings.Contains(body, "host-a") {
		t.Error("bob must not see alice's host (host-a) in the list")
	}
}

func TestWebHostBlock_NonOwnerForbidden(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob, foreignHost, ownHost := twoTenants(t, w, s)

	// CSRF token from a page bob can load (his own host detail).
	token, cookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/"+ownHost, []*http.Cookie{bob})

	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/"+foreignHost+"/block", strings.NewReader("_csrf="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("block foreign host: status = %d, want 403", rec.Code)
	}
	got, err := s.GetHost(context.Background(), foreignHost)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status == models.HostStatusBlocked {
		t.Error("foreign host was blocked despite the 403")
	}
}

func TestWebHostDelete_NonOwnerForbidden(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob, foreignHost, ownHost := twoTenants(t, w, s)

	token, cookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/"+ownHost, []*http.Cookie{bob})

	req := httptest.NewRequest(http.MethodDelete, "/ui/hosts/"+foreignHost, nil)
	req.Header.Set("X-CSRF-Token", token)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("delete foreign host: status = %d, want 403", rec.Code)
	}
	// The foreign host must still exist.
	if _, err := s.GetHost(context.Background(), foreignHost); err != nil {
		t.Errorf("foreign host was deleted despite the 403: %v", err)
	}
}

func TestWebNetworks_ListScopedToOwner(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob, _, _ := twoTenants(t, w, s) // creates net-a (alice) and net-b (bob)

	req := httptest.NewRequest(http.MethodGet, "/ui/networks", nil)
	req.AddCookie(bob)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("networks list: status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "net-b") {
		t.Error("bob should see his own network (net-b)")
	}
	if strings.Contains(body, "net-a") {
		t.Error("bob must not see alice's network (net-a)")
	}
}

// TestWebNetworkCreate_ErrorRerenderScoped pins that the create-form error
// re-render (renderNetworksError) scopes the network list — a validation error
// must not leak another tenant's networks.
func TestWebNetworkCreate_ErrorRerenderScoped(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob, _, ownHost := twoTenants(t, w, s)

	// CSRF token from a page bob can load.
	token, cookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/"+ownHost, []*http.Cookie{bob})

	// Empty name triggers renderNetworksError (handlers.go:1318).
	req := httptest.NewRequest(http.MethodPost, "/ui/networks", strings.NewReader("_csrf="+token+"&name="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "net-a") {
		t.Error("network create error re-render leaked alice's network (net-a)")
	}
}

func TestWebHosts_AdminSeesAllTenants(t *testing.T) {
	w, s := newSettingsWeb(t)
	admin := authedSession(t, s, "root", "admin")
	authedSession(t, s, "alice", "user")
	authedSession(t, s, "bob", "user")
	_, _, foreignToAdmin := seedTenant(t, s, "op-alice", "a")
	seedTenant(t, s, "op-bob", "b")

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts", nil)
	req.AddCookie(admin)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "host-a") || !strings.Contains(body, "host-b") {
		t.Error("admin should see every tenant's hosts in the list")
	}
	if code := webGET(t, w, "/ui/hosts/"+foreignToAdmin, admin); code != http.StatusOK {
		t.Errorf("admin host detail for any host: status = %d, want 200", code)
	}
}

// TestWebHost_EmptyCAIDHiddenFromNonAdmin pins the issue-#93 legacy case: a
// pre-multi-CA host (blank ca_id) is hidden from non-admins, who also can't
// reach its detail page.
func TestWebHost_EmptyCAIDHiddenFromNonAdmin(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob := authedSession(t, s, "bob", "user")
	seedTenant(t, s, "op-bob", "b") // bob owns net-b/host-b

	ctx := context.Background()
	now := time.Now()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "net-legacy", Name: "net-legacy", CIDRs: []string{"10.9.0.0/24"}, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHost(ctx, &models.Host{
		ID: "host-legacy", NetworkID: "net-legacy", CAID: "", Name: "host-legacy",
		Role: models.HostRoleHost, Status: models.HostStatusPending, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ui/hosts", nil)
	req.AddCookie(bob)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "host-legacy") {
		t.Error("non-admin must not see a legacy empty-ca_id host in the list")
	}
	if code := webGET(t, w, "/ui/hosts/host-legacy", bob); code != http.StatusForbidden {
		t.Errorf("legacy host detail for non-admin: status = %d, want 403", code)
	}
}

// webGET issues an authenticated GET and returns the status code.
func webGET(t *testing.T, w *Web, path string, cookie *http.Cookie) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec.Code
}
