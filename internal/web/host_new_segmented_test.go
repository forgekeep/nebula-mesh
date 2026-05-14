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
)

// TestHostNewForm_SegmentedWidgetHooks asserts that the rendered host_new
// template carries the marker hooks the JS widget needs to swap the
// free-form text input for the segmented variants (issue #100). The Go
// test cannot execute the JS, but breaking the hook contract is enough
// to silently degrade the UI — guarded here.
func TestHostNewForm_SegmentedWidgetHooks(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	for _, n := range []*models.Network{
		{ID: "n-24", Name: "v4-24", CIDR: "10.42.0.0/24", CreatedAt: time.Now()},
		{ID: "n-22", Name: "v4-22", CIDR: "10.44.0.0/22", CreatedAt: time.Now()},
		{ID: "n-64", Name: "v6-64", CIDR: "fd00:42::/64", CreatedAt: time.Now()},
	} {
		if err := s.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest("GET", "/ui/hosts/new", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// Required DOM hooks. The widget mounts into #nebula-ip-segments, the
	// text input stays as the canonical form field, and the hint stays for
	// the fallback path.
	for _, hook := range []string{
		`id="nebula-ip-segments"`,
		`id="nebula-ip-input"`,
		`id="nebula-ip-hint"`,
		`id="network-select"`,
		`id="host-form"`,
	} {
		if !strings.Contains(body, hook) {
			t.Errorf("template should contain %s; not found", hook)
		}
	}

	// JS branch names — guard against silent refactor regressions that
	// would drop one of the issue-100 variants.
	for _, marker := range []string{
		"mountIPv4Octets",
		"mountIPv4Bounded",
		"mountIPv6Segments",
		"chooseWidget",
		"computeByteAlignedPrefix", // legacy hook kept for issue #97 test
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("template should contain JS helper %s; not found", marker)
		}
	}
}

// TestHostCreate_FriendlyNebulaIPInline confirms the friendly wrapper
// reaches the inline error banner instead of raw Go ParseAddr text.
func TestHostCreate_FriendlyNebulaIPInline(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-friendly", Name: "n", CIDR: "10.0.0.0/24", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id": {"n-friendly"},
		"name":       {"bad-ip"},
		"nebula_ip":  {"10.42.0.22.333"},
		"role":       {"host"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "ParseAddr") {
		t.Errorf("body must not leak the stdlib ParseAddr text; got:\n%s", body)
	}
	if !strings.Contains(body, "10.42.0.22.333") || !strings.Contains(body, "not a valid IPv4 or IPv6 address") {
		t.Errorf("body should render the friendly error; got:\n%s", body)
	}
}

// TestHostCreate_FriendlyPublicIPInline guards the public_ip wrapper.
func TestHostCreate_FriendlyPublicIPInline(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-pub", Name: "n", CIDR: "10.0.0.0/24", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id":  {"n-pub"},
		"name":        {"lh"},
		"nebula_ip":   {"10.0.0.5"},
		"role":        {"lighthouse"},
		"public_ip":   {"203.0.113.999"},
		"listen_port": {"4242"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "ParseAddr") {
		t.Errorf("body must not leak the stdlib ParseAddr text; got:\n%s", body)
	}
	if !strings.Contains(body, "public_ip") || !strings.Contains(body, "203.0.113.999") {
		t.Errorf("body should mention the field and bad value; got:\n%s", body)
	}
}

// TestHostCreate_FriendlyAdvancedListenHostInline guards the
// adv_listen_host wrapper now that web also runs ValidateHostAdvanced.
func TestHostCreate_FriendlyAdvancedListenHostInline(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-adv", Name: "n", CIDR: "10.0.0.0/24", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id":      {"n-adv"},
		"name":            {"adv"},
		"nebula_ip":       {"10.0.0.5"},
		"role":            {"host"},
		"adv_listen_host": {"not-an-ip"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "ParseAddr") {
		t.Errorf("body must not leak the stdlib ParseAddr text; got:\n%s", body)
	}
	if !strings.Contains(body, "advanced.listen_host") {
		t.Errorf("body should mention the offending field; got:\n%s", body)
	}
}
