package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func advForm(t *testing.T, values url.Values) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestParseAdvancedFromForm_FirewallInbound(t *testing.T) {
	req := advForm(t, url.Values{
		"adv_firewall_inbound": {"443/tcp from web\n\n8000-9000/udp from monitoring\nany/icmp from any"},
	})
	adv, err := parseAdvancedFromForm(req)
	if err != nil {
		t.Fatalf("parseAdvancedFromForm: %v", err)
	}
	if adv == nil {
		t.Fatal("adv = nil, want parsed rules")
	}
	want := []models.HostFirewallRule{
		{Port: "443", Proto: "tcp", Group: "web"},
		{Port: "8000-9000", Proto: "udp", Group: "monitoring"},
		{Port: "any", Proto: "icmp", Group: "any"},
	}
	if len(adv.FirewallInbound) != len(want) {
		t.Fatalf("rules = %+v, want %+v", adv.FirewallInbound, want)
	}
	for i := range want {
		if adv.FirewallInbound[i] != want[i] {
			t.Errorf("rule[%d] = %+v, want %+v", i, adv.FirewallInbound[i], want[i])
		}
	}
}

func TestParseAdvancedFromForm_FirewallInbound_Malformed(t *testing.T) {
	cases := []string{
		"443 tcp web",            // missing slash and "from"
		"443/tcp web",            // missing "from"
		"443/tcp/extra from web", // two slashes
		"443 from web",           // no proto
	}
	for _, line := range cases {
		t.Run(line, func(t *testing.T) {
			req := advForm(t, url.Values{"adv_firewall_inbound": {line}})
			_, err := parseAdvancedFromForm(req)
			if err == nil {
				t.Fatalf("line %q accepted, want error", line)
			}
			if !strings.Contains(err.Error(), "<PORT>/<PROTO> from <GROUP>") {
				t.Errorf("error %q should explain the expected format", err)
			}
		})
	}
}

func TestParseAdvancedFromForm_FirewallInbound_EmptyIsNil(t *testing.T) {
	req := advForm(t, url.Values{"adv_firewall_inbound": {"   \n  "}})
	adv, err := parseAdvancedFromForm(req)
	if err != nil {
		t.Fatalf("parseAdvancedFromForm: %v", err)
	}
	if adv != nil {
		t.Errorf("adv = %+v, want nil for whitespace-only textarea", adv)
	}
}

func TestHostFormState_FirewallInboundRoundTrip(t *testing.T) {
	h := &models.Host{
		Name: "h", NebulaIPs: []string{"10.0.0.1"},
		Advanced: &models.HostAdvanced{
			FirewallInbound: []models.HostFirewallRule{
				{Port: "443", Proto: "tcp", Group: "web"},
				{Port: "any", Proto: "icmp", Group: "any"},
			},
		},
	}
	state := hostFormStateFromHost(h)
	want := "443/tcp from web\nany/icmp from any"
	if state.AdvFirewallInbound != want {
		t.Errorf("AdvFirewallInbound = %q, want %q", state.AdvFirewallInbound, want)
	}
}

func TestHostForms_FirewallInboundTextarea(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-fw1", Name: "test-net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	host := &models.Host{
		ID: "h-fw1", NetworkID: "n-fw1", Name: "fw-1", NebulaIPs: []string{"10.0.0.5"},
		Groups: []string{}, Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		Advanced: &models.HostAdvanced{
			FirewallInbound: []models.HostFirewallRule{{Port: "443", Proto: "tcp", Group: "web"}},
		},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/ui/hosts/new", "/ui/hosts/h-fw1/edit"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), `name="adv_firewall_inbound"`) {
				t.Error("form should include the adv_firewall_inbound textarea")
			}
		})
	}

	// Edit form shows the existing rules and opens the advanced section.
	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-fw1/edit", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "443/tcp from web") {
		t.Error("edit form should show the existing firewall rules")
	}
	if !strings.Contains(body, "<details style=\"margin: 16px 0;\" open>") {
		t.Error("advanced section should be open when firewall rules are set")
	}
}

func TestCreateHostViaUI_FirewallInbound(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-fw2", Name: "test-net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
	form := url.Values{
		"network_id":           {"n-fw2"},
		"name":                 {"fw-created"},
		"nebula_ips":           {"10.0.0.6"},
		"role":                 {"host"},
		"adv_firewall_inbound": {"22/tcp from admin\n443/tcp from web"},
		"_csrf":                {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
	}

	hosts, err := s.ListHosts(ctx, store.HostFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var created *models.Host
	for _, h := range hosts {
		if h.Name == "fw-created" {
			created = h
			break
		}
	}
	if created == nil {
		t.Fatal("host \"fw-created\" not found")
	}
	want := []models.HostFirewallRule{
		{Port: "22", Proto: "tcp", Group: "admin"},
		{Port: "443", Proto: "tcp", Group: "web"},
	}
	if created.Advanced == nil || len(created.Advanced.FirewallInbound) != 2 {
		t.Fatalf("Advanced.FirewallInbound = %+v, want %+v", created.Advanced, want)
	}
	for i := range want {
		if created.Advanced.FirewallInbound[i] != want[i] {
			t.Errorf("rule[%d] = %+v, want %+v", i, created.Advanced.FirewallInbound[i], want[i])
		}
	}
}

func TestCreateHostViaUI_FirewallInbound_InvalidRerenders(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-fw3", Name: "test-net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
	form := url.Values{
		"network_id":           {"n-fw3"},
		"name":                 {"fw-bad"},
		"nebula_ips":           {"10.0.0.7"},
		"role":                 {"host"},
		"adv_firewall_inbound": {"443/sctp from web"},
		"_csrf":                {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "advanced.firewall_inbound[0]") {
		t.Errorf("error banner should reference the offending rule\n%s", body)
	}
	if !strings.Contains(body, "443/sctp from web") {
		t.Errorf("re-rendered form should preserve the submitted textarea input\n%s", body)
	}
}

// TestParseAdvancedFromForm_FirewallInbound_CIDRClauses covers the cidr= and
// local_cidr= clauses of the textarea grammar.
func TestParseAdvancedFromForm_FirewallInbound_CIDRClauses(t *testing.T) {
	req := advForm(t, url.Values{
		"adv_firewall_inbound": {
			"443/tcp from web local_cidr=192.168.50.0/24\n" +
				"22/tcp cidr=10.0.0.0/24\n" +
				"any/icmp cidr=any local_cidr=any\n" +
				"53/udp local_cidr=fd00::/8 from dns",
		},
	})
	adv, err := parseAdvancedFromForm(req)
	if err != nil {
		t.Fatalf("parseAdvancedFromForm: %v", err)
	}
	want := []models.HostFirewallRule{
		{Port: "443", Proto: "tcp", Group: "web", LocalCidr: "192.168.50.0/24"},
		{Port: "22", Proto: "tcp", Cidr: "10.0.0.0/24"},
		{Port: "any", Proto: "icmp", Cidr: "any", LocalCidr: "any"},
		{Port: "53", Proto: "udp", Group: "dns", LocalCidr: "fd00::/8"},
	}
	if len(adv.FirewallInbound) != len(want) {
		t.Fatalf("rules = %+v, want %+v", adv.FirewallInbound, want)
	}
	for i := range want {
		if adv.FirewallInbound[i] != want[i] {
			t.Errorf("rule[%d] = %+v, want %+v", i, adv.FirewallInbound[i], want[i])
		}
	}
}

func TestParseAdvancedFromForm_FirewallInbound_CIDRMalformed(t *testing.T) {
	cases := map[string]string{
		"no selector at all":        "443/tcp local_cidr=10.0.0.0/24",
		"group and cidr together":   "443/tcp from web cidr=10.0.0.0/24",
		"from without a group":      "443/tcp from",
		"duplicate cidr":            "443/tcp cidr=10.0.0.0/24 cidr=10.1.0.0/24",
		"duplicate local_cidr":      "443/tcp from web local_cidr=any local_cidr=any",
		"duplicate from":            "443/tcp from web from ops",
		"unknown clause":            "443/tcp from web zone=dmz",
		"bare cidr without keyword": "443/tcp 10.0.0.0/24",
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			req := advForm(t, url.Values{"adv_firewall_inbound": {line}})
			if _, err := parseAdvancedFromForm(req); err == nil {
				t.Fatalf("line %q accepted, want error", line)
			}
		})
	}
}

// TestHostFormState_FirewallInboundCIDRRoundTrip guards that rendering a rule
// back into the textarea produces a line the parser accepts unchanged.
func TestHostFormState_FirewallInboundCIDRRoundTrip(t *testing.T) {
	rules := []models.HostFirewallRule{
		{Port: "443", Proto: "tcp", Group: "web", LocalCidr: "192.168.50.0/24"},
		{Port: "22", Proto: "tcp", Cidr: "10.0.0.0/24"},
		{Port: "any", Proto: "icmp", Group: "any", LocalCidr: "any"},
	}
	h := &models.Host{
		Name: "h", NebulaIPs: []string{"10.0.0.1"},
		Advanced: &models.HostAdvanced{FirewallInbound: rules},
	}
	state := hostFormStateFromHost(h)
	want := "443/tcp from web local_cidr=192.168.50.0/24\n" +
		"22/tcp cidr=10.0.0.0/24\n" +
		"any/icmp from any local_cidr=any"
	if state.AdvFirewallInbound != want {
		t.Fatalf("AdvFirewallInbound = %q, want %q", state.AdvFirewallInbound, want)
	}

	// Feeding the rendered text back through the parser must reproduce the
	// original rules — otherwise an unrelated host edit would mutate them.
	req := advForm(t, url.Values{"adv_firewall_inbound": {state.AdvFirewallInbound}})
	adv, err := parseAdvancedFromForm(req)
	if err != nil {
		t.Fatalf("reparsing rendered text: %v", err)
	}
	for i := range rules {
		if adv.FirewallInbound[i] != rules[i] {
			t.Errorf("round-trip rule[%d] = %+v, want %+v", i, adv.FirewallInbound[i], rules[i])
		}
	}
}

// TestParseAdvancedFromForm_FirewallInbound_ClauseAsGroupRejected pins that a
// clause keyword cannot be swallowed as a group name. `from cidr=10.0.0.0/24`
// is a plausible mistyping of the prefix selector; accepting it would define a
// group no certificate can carry, yielding a rule that silently matches
// nothing instead of the prefix rule the operator meant.
func TestParseAdvancedFromForm_FirewallInbound_ClauseAsGroupRejected(t *testing.T) {
	for _, line := range []string{
		"443/tcp from cidr=10.0.0.0/24",
		"443/tcp from local_cidr=any",
	} {
		t.Run(line, func(t *testing.T) {
			req := advForm(t, url.Values{"adv_firewall_inbound": {line}})
			adv, err := parseAdvancedFromForm(req)
			if err == nil {
				t.Fatalf("line %q accepted as group %q, want error", line, adv.FirewallInbound[0].Group)
			}
		})
	}

	// The correct spelling of the same intent still works.
	req := advForm(t, url.Values{"adv_firewall_inbound": {"443/tcp cidr=10.0.0.0/24"}})
	adv, err := parseAdvancedFromForm(req)
	if err != nil {
		t.Fatalf("valid prefix rule rejected: %v", err)
	}
	if adv.FirewallInbound[0].Cidr != "10.0.0.0/24" || adv.FirewallInbound[0].Group != "" {
		t.Errorf("rule = %+v, want cidr 10.0.0.0/24 and no group", adv.FirewallInbound[0])
	}
}
