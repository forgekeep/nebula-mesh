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
		{ID: "n-24", Name: "v4-24", CIDRs: []string{"10.42.0.0/24"}, CreatedAt: time.Now()},
		{ID: "n-22", Name: "v4-22", CIDRs: []string{"10.44.0.0/22"}, CreatedAt: time.Now()},
		{ID: "n-64", Name: "v6-64", CIDRs: []string{"fd00:42::/64"}, CreatedAt: time.Now()},
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

	// Required DOM hooks for repeatable IP rows (new design).
	// The rows container, network selector, and row add/remove handlers must be present.
	for _, hook := range []string{
		`id="nebula-ip-rows"`,
		`id="network-select"`,
		`id="host-form"`,
	} {
		if !strings.Contains(body, hook) {
			t.Errorf("template should contain %s; not found", hook)
		}
	}

	// JS row add/remove handlers for repeatable IP addresses.
	for _, marker := range []string{
		`data-action="add-ip"`,
		`data-action="remove"`,
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("template should contain %s; not found", marker)
		}
	}
}

// TestHostCreate_FriendlyNebulaIPInline confirms the friendly wrapper
// reaches the inline error banner instead of raw Go ParseAddr text.
func TestHostCreate_FriendlyNebulaIPInline(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-friendly", Name: "n", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id": {"n-friendly"},
		"name":       {"bad-ip"},
		"nebula_ips":  {"10.42.0.22.333"},
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
		ID: "n-pub", Name: "n", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id":  {"n-pub"},
		"name":        {"lh"},
		"nebula_ips":   {"10.0.0.5"},
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
		ID: "n-adv", Name: "n", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id":      {"n-adv"},
		"name":            {"adv"},
		"nebula_ips":       {"10.0.0.5"},
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

// TestHandleHostNew_FormHasKindFields verifies that the host creation form
// renders Kind and Variant select elements with correct options.
func TestHandleHostNew_FormHasKindFields(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:    "n-form-test",
		Name:  "form-test",
		CIDRs: []string{"10.0.0.0/24"},
		CAID:  "ca-test",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/ui/hosts/new", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()

	if !strings.Contains(body, `name="kind"`) {
		t.Error("response should contain Kind select")
	}
	if !strings.Contains(body, `value="agent"`) {
		t.Error("response should contain agent kind option")
	}
	if !strings.Contains(body, `value="mobile"`) {
		t.Error("response should contain mobile kind option")
	}

	if !strings.Contains(body, `name="variant"`) {
		t.Error("response should contain Variant select")
	}
	if !strings.Contains(body, `value="ios"`) {
		t.Error("response should contain ios variant option")
	}
	if !strings.Contains(body, `value="android"`) {
		t.Error("response should contain android variant option")
	}
}

// TestHandleHostNew_PreservesKindOnError verifies that when form submission
// fails validation, the Kind and Variant fields are preserved in the re-rendered form.
func TestHandleHostNew_PreservesKindOnError(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	network := &models.Network{
		ID:    "n-test",
		Name:  "test-net",
		CIDRs: []string{"10.0.0.0/24"},
		CAID:  "ca-test",
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id": {"n-test"},
		"name":       {"invalid-host"},
		"nebula_ips":  {"10.0.0.5"},
		"kind":       {"mobile"},
		"variant":    {"ios"},
		"role":       {"lighthouse"},
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

	if !strings.Contains(body, `<option value="mobile" selected`) {
		t.Error("response should have mobile option selected when form rerendered with mobile kind")
	}
	if !strings.Contains(body, `<option value="ios" selected`) {
		t.Error("response should have ios option selected when form rerendered with ios variant")
	}
}
