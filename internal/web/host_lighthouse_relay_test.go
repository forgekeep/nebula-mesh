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

// TestHostForms_OfferLighthouseRelayOption: both the create and edit forms
// must offer the combined lighthouse+relay role in the role select.
func TestHostForms_OfferLighthouseRelayOption(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-lr", Name: "test-net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	host := &models.Host{
		ID: "h-lr", NetworkID: "n-lr", Name: "lr-1", NebulaIPs: []string{"10.0.0.9"},
		Groups: []string{}, Role: models.HostRoleLighthouseRelay,
		IsLighthouse: true, IsRelay: true,
		PublicIP: "203.0.113.9", ListenPort: 4242,
		Status: models.HostStatusEnrolled, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/ui/hosts/new", "/ui/hosts/h-lr/edit"} {
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
			if !strings.Contains(rec.Body.String(), `<option value="lighthouse+relay"`) {
				t.Error("role select should offer the lighthouse+relay option")
			}
		})
	}

	// The edit form must preselect the host's combined role.
	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-lr/edit", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `<option value="lighthouse+relay" selected`) &&
		!strings.Contains(rec.Body.String(), `<option value="lighthouse+relay"selected`) {
		t.Error("edit form should preselect lighthouse+relay for this host")
	}
}

// TestCreateHostViaUI_LighthouseRelay: creating a host through the web form
// with role=lighthouse+relay must persist both IsLighthouse and IsRelay.
func TestCreateHostViaUI_LighthouseRelay(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-lr2", Name: "test-net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
	form := url.Values{
		"network_id":  {"n-lr2"},
		"name":        {"lr-created"},
		"nebula_ips":  {"10.0.0.10"},
		"role":        {"lighthouse+relay"},
		"public_ip":   {"203.0.113.10"},
		"listen_port": {"4242"},
		"_csrf":       {csrfToken},
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

	created := findHostByName(t, s, "lr-created")
	if created.Role != models.HostRoleLighthouseRelay {
		t.Errorf("role = %q, want %q", created.Role, models.HostRoleLighthouseRelay)
	}
	if !created.IsLighthouse || !created.IsRelay {
		t.Errorf("IsLighthouse=%v IsRelay=%v, want true/true", created.IsLighthouse, created.IsRelay)
	}
}

// TestCreateHostViaUI_LighthouseRelay_RequiresReachability: the combined
// role inherits the public_ip/listen_port guard.
func TestCreateHostViaUI_LighthouseRelay_RequiresReachability(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-lr3", Name: "test-net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
	form := url.Values{
		"network_id": {"n-lr3"},
		"name":       {"lr-bad"},
		"nebula_ips": {"10.0.0.11"},
		"role":       {"lighthouse+relay"},
		"_csrf":      {csrfToken},
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
	if !strings.Contains(rec.Body.String(), "public_ip") {
		t.Errorf("body should mention public_ip, got: %s", rec.Body.String())
	}
}

// TestHostUpdate_POST_LighthouseRelay: editing a host to role=lighthouse+relay
// must re-derive both booleans; editing back to host must clear them.
func TestHostUpdate_POST_LighthouseRelay(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-lr4", Name: "test-net", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	host := &models.Host{
		ID: "h-lr4", NetworkID: "n-lr4", Name: "lr-edit", NebulaIPs: []string{"10.0.0.12"},
		Groups: []string{}, Role: models.HostRoleHost,
		Status: models.HostStatusEnrolled, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(ctx, host); err != nil {
		t.Fatal(err)
	}

	postEdit := func(role, publicIP, listenPort string) {
		t.Helper()
		csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/h-lr4/edit", cookies)
		form := url.Values{
			"network_id":  {"n-lr4"},
			"name":        {"lr-edit"},
			"nebula_ips":  {"10.0.0.12"},
			"role":        {role},
			"public_ip":   {publicIP},
			"listen_port": {listenPort},
			"_csrf":       {csrfToken},
		}
		req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-lr4/edit", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range updatedCookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("edit to role=%s: status = %d, want 303, body: %s", role, rec.Code, rec.Body.String())
		}
	}

	postEdit("lighthouse+relay", "203.0.113.12", "4242")
	updated, err := s.GetHost(ctx, "h-lr4")
	if err != nil {
		t.Fatal(err)
	}
	if !updated.IsLighthouse || !updated.IsRelay {
		t.Errorf("after edit to lighthouse+relay: IsLighthouse=%v IsRelay=%v, want true/true",
			updated.IsLighthouse, updated.IsRelay)
	}

	postEdit("host", "", "")
	reverted, err := s.GetHost(ctx, "h-lr4")
	if err != nil {
		t.Fatal(err)
	}
	if reverted.IsLighthouse || reverted.IsRelay {
		t.Errorf("after edit back to host: IsLighthouse=%v IsRelay=%v, want false/false",
			reverted.IsLighthouse, reverted.IsRelay)
	}
}

func findHostByName(t *testing.T, s *store.SQLiteStore, name string) *models.Host {
	t.Helper()
	hosts, err := s.ListHosts(context.Background(), store.HostFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("host %q not found", name)
	return nil
}
