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

// TestHostCreate_InlineErrorPreservesForm — issue #91. On a host-create
// validation failure the server must re-render host_new.html (not a
// bare 400 error page), preserve the operator's input, and show the
// error inline.
func TestHostCreate_InlineErrorPreservesForm(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "net-inline", Name: "test", CIDR: "10.0.0.0/24", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// Submit a duplicate-IP / out-of-CIDR error to exercise the
	// nebula_ip branch. 10.0.0.300 is not a valid IPv4 address, which
	// trips netip.ParseAddr inside validateHostIPForNetwork.
	form := url.Values{
		"network_id":      {"net-inline"},
		"name":            {"preserved-name"},
		"nebula_ip":       {"10.99.99.99"}, // outside 10.0.0.0/24
		"role":            {"host"},
		"groups":          {"web, prod"},
		"adv_listen_host": {"0.0.0.0"},
	}
	req := httptest.NewRequest("POST", "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// Re-rendered the form, not a bare error page.
	if !strings.Contains(body, `name="name"`) || !strings.Contains(body, `name="nebula_ip"`) {
		t.Fatalf("body is not the host_new form:\n%s", body)
	}
	// Submitted values preserved.
	if !strings.Contains(body, `value="preserved-name"`) {
		t.Errorf("body should preserve submitted Name field: missing value=\"preserved-name\"")
	}
	if !strings.Contains(body, `value="10.99.99.99"`) {
		t.Errorf("body should preserve submitted nebula_ip field")
	}
	if !strings.Contains(body, `value="web, prod"`) {
		t.Errorf("body should preserve submitted groups field")
	}
	// Selected network is sticky.
	if !strings.Contains(body, `value="net-inline" selected`) {
		t.Errorf("selected network option should be marked selected:\n%s", body)
	}
	// Error banner is rendered with the actual reason from validateHostIP.
	if !strings.Contains(body, `role="alert"`) {
		t.Errorf("body should render alert banner; got:\n%s", body)
	}
}

func TestHostCreate_InlineErrorPreservesRole(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "net-role", Name: "n", CIDR: "10.0.0.0/24", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"network_id": {"net-role"},
		"name":       {"lh-1"},
		"nebula_ip":  {"10.0.0.5"},
		"role":       {"lighthouse"}, // requires public_ip + listen_port → fails
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
	if !strings.Contains(body, `value="lighthouse" selected`) {
		t.Errorf("body should preserve selected role=lighthouse:\n%s", body)
	}
	if !strings.Contains(body, "public_ip") {
		t.Errorf("body should explain why the form failed; missing the word 'public_ip'")
	}
}

// TestNetworkCreate_InlineErrorPreservesForm — issue #91 for the network
// create form (which lives expanded on /ui/networks).
func TestNetworkCreate_InlineErrorPreservesForm(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	form := url.Values{
		"name": {"prod-net"},
		"cidr": {"not-a-cidr"},
	}
	req := httptest.NewRequest("POST", "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	if !strings.Contains(body, `value="prod-net"`) {
		t.Errorf("body should preserve submitted Name")
	}
	if !strings.Contains(body, `value="not-a-cidr"`) {
		t.Errorf("body should preserve submitted CIDR")
	}
	if !strings.Contains(body, `role="alert"`) {
		t.Errorf("body should render alert banner")
	}
	if !strings.Contains(body, `invalid CIDR`) {
		t.Errorf("body should contain the actual error explanation; got:\n%s", body)
	}
	// The create form should not be hidden on validation error.
	if strings.Contains(body, `id="new-network" class="card" style="display:none"`) {
		t.Errorf("create form should be visible (not display:none) on validation error")
	}
}

func TestNetworkCreate_InlineErrorRequiredFields(t *testing.T) {
	w, _ := newTestWeb(t)
	cookies := loginSession(t, w)

	form := url.Values{
		"name": {""},
		"cidr": {""},
	}
	req := httptest.NewRequest("POST", "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `name and cidr are required`) {
		t.Errorf("body should explain missing fields; got:\n%s", rec.Body.String())
	}
}
