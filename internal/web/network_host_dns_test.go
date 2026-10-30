package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/hostdns"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func postNetworkForm(t *testing.T, w *Web, cookies []*http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	token, updated := getCSRFTokenFromCookies(t, w, "/ui/networks", cookies)
	form.Set("_csrf", token)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updated {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec
}

func storedHostDNS(t *testing.T, s store.Store, networkID string) (string, bool) {
	t.Helper()
	raw, err := s.GetNetworkConfig(context.Background(), networkID, hostdns.StoreKey)
	if errors.Is(err, store.ErrNotFound) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return raw, true
}

func seedPlainNetwork(t *testing.T, s store.Store) {
	t.Helper()
	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-dns", Name: "dns-net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkHostDNS_SetChangeAndTurnOff(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedPlainNetwork(t, s)
	ctx := context.Background()
	const path = "/ui/networks/n-dns/host-dns"

	before, _ := s.GetNetworkConfigVersion(ctx, "n-dns")
	rec := postNetworkForm(t, w, cookies, path, url.Values{
		"host_dns_nameservers":    {"10.0.0.53\n10.0.0.54"},
		"host_dns_match_domains":  {"Mesh.Example"},
		"host_dns_search_domains": {""},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("set: %d %s", rec.Code, rec.Body.String())
	}
	raw, ok := storedHostDNS(t, s, "n-dns")
	if !ok || !strings.Contains(raw, `"10.0.0.54"`) || !strings.Contains(raw, `"mesh.example"`) {
		t.Fatalf("stored = %q", raw)
	}
	set, _ := s.GetNetworkConfigVersion(ctx, "n-dns")
	if set <= before {
		t.Error("saving host DNS did not move the network config version")
	}

	page := getPage(t, w, cookies, "/ui/networks")
	if !strings.Contains(page, "10.0.0.53, 10.0.0.54 for mesh.example") || !strings.Contains(page, "Experimental in Nebula") {
		t.Errorf("networks page does not show the setting:\n%s", page)
	}

	// The same values save nothing, so hosts are not woken for no change.
	rec = postNetworkForm(t, w, cookies, path, url.Values{
		"host_dns_nameservers":   {"10.0.0.53, 10.0.0.54"},
		"host_dns_match_domains": {"mesh.example"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("resave: %d", rec.Code)
	}
	if again, _ := s.GetNetworkConfigVersion(ctx, "n-dns"); again != set {
		t.Errorf("unchanged save moved the version from %d to %d", set, again)
	}

	if rec := postNetworkForm(t, w, cookies, path, url.Values{}); rec.Code != http.StatusSeeOther {
		t.Fatalf("turn off: %d %s", rec.Code, rec.Body.String())
	}
	raw, _ = storedHostDNS(t, s, "n-dns")
	if !strings.Contains(raw, `"nameservers":[]`) {
		t.Errorf("stored after turning off = %q", raw)
	}
	if off, _ := s.GetNetworkConfigVersion(ctx, "n-dns"); off <= set {
		t.Error("turning host DNS off did not move the network config version")
	}
	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if e.Action == "network.host_dns.update" && e.Resource == "n-dns" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("audit entries = %d, want 2", count)
	}
}

func TestNetworkHostDNS_InvalidEditKeepsStoredValue(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedPlainNetwork(t, s)
	const good = `{"nameservers":["10.0.0.53"],"match_domains":["mesh.example"],"search_domains":[]}`
	if err := s.SetNetworkConfig(context.Background(), "n-dns", hostdns.StoreKey, good); err != nil {
		t.Fatal(err)
	}

	rec := postNetworkForm(t, w, cookies, "/ui/networks/n-dns/host-dns", url.Values{
		"host_dns_nameservers":   {"0.0.0.0"},
		"host_dns_match_domains": {"*.mesh.example"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "nebula would reject this host dns") || !strings.Contains(body, "*.mesh.example") || !strings.Contains(body, "<details open>") {
		t.Errorf("form does not come back with the reason and the input:\n%s", body)
	}
	if raw, _ := storedHostDNS(t, s, "n-dns"); raw != good {
		t.Errorf("stored = %q, want it unchanged", raw)
	}
}

func createNetworkForm(extra url.Values) url.Values {
	form := url.Values{"name": {"with-dns"}, "cidrs": {"10.9.0.0/24"}}
	for k, v := range extra {
		form[k] = v
	}
	return form
}

func TestNetworkCreate_WithHostDNS(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	seedActiveCA(t, s, "ca-alice", "op-alice", "alice-ca")
	ctx := context.Background()
	cookies := []*http.Cookie{cookie}

	rec := postNetworkForm(t, w, cookies, "/ui/networks", createNetworkForm(url.Values{
		"host_dns_nameservers":   {"10.9.0.53"},
		"host_dns_match_domains": {"mesh.example"},
	}))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	networks, err := s.ListNetworks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 1 {
		t.Fatalf("networks = %d, want 1", len(networks))
	}
	if raw, ok := storedHostDNS(t, s, networks[0].ID); !ok || !strings.Contains(raw, "10.9.0.53") {
		t.Errorf("stored = %q", raw)
	}
}

func TestNetworkCreate_NoHostDNSStoresNothing(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	seedActiveCA(t, s, "ca-alice", "op-alice", "alice-ca")
	if rec := postNetworkForm(t, w, []*http.Cookie{cookie}, "/ui/networks", createNetworkForm(nil)); rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	networks, _ := s.ListNetworks(context.Background())
	if len(networks) != 1 {
		t.Fatalf("networks = %d, want 1", len(networks))
	}
	if raw, ok := storedHostDNS(t, s, networks[0].ID); ok {
		t.Errorf("stored = %q, want nothing", raw)
	}
}

func TestNetworkCreate_InvalidHostDNSCreatesNoNetwork(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "alice", "user")
	seedActiveCA(t, s, "ca-alice", "op-alice", "alice-ca")

	rec := postNetworkForm(t, w, []*http.Cookie{cookie}, "/ui/networks", createNetworkForm(url.Values{
		"host_dns_nameservers": {"10.9.0.53"},
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "match_domains must list at least one domain") || !strings.Contains(body, "10.9.0.53") || !strings.Contains(body, `value="with-dns"`) {
		t.Errorf("form does not keep the reason and input:\n%s", body)
	}
	networks, err := s.ListNetworks(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(networks) != 0 {
		t.Errorf("networks = %d, want none", len(networks))
	}
}

// SEC-TENANT-001: a non-owner cannot change a foreign network's host DNS.
func TestNetworkHostDNS_SEC_TENANT_001_NonOwnerForbidden(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob, foreignHost, _ := twoTenants(t, w, s)
	host, err := s.GetHost(context.Background(), foreignHost)
	if err != nil {
		t.Fatal(err)
	}
	foreignNetwork := host.NetworkID

	rec := postNetworkForm(t, w, []*http.Cookie{bob}, "/ui/networks/"+foreignNetwork+"/host-dns", url.Values{
		"host_dns_nameservers":   {"10.0.0.53"},
		"host_dns_match_domains": {"mesh.example"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if raw, ok := storedHostDNS(t, s, foreignNetwork); ok {
		t.Errorf("foreign network changed despite the 403: %q", raw)
	}
}

func TestNetworkHostDNS_UnknownNetwork(t *testing.T) {
	w, _ := newTestWeb(t)
	rec := postNetworkForm(t, w, loginSession(t, w), "/ui/networks/nope/host-dns", url.Values{})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func getPage(t *testing.T, w *Web, cookies []*http.Cookie, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status = %d", path, rec.Code)
	}
	return rec.Body.String()
}
