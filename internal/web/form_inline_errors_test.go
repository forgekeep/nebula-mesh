package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// hasSelectedOption reports whether body contains an <option> element with
// value="<value>" that also carries the `selected` attribute. Other
// attributes (data-cidr, name, …) between value and selected are allowed.
func hasSelectedOption(body, value string) bool {
	re := regexp.MustCompile(`<option [^>]*value="` + regexp.QuoteMeta(value) + `"[^>]* selected`)
	return re.MatchString(body)
}

// TestHostCreate_InlineErrorPreservesForm — issue #91. On a host-create
// validation failure the server must re-render host_new.html (not a
// bare 400 error page), preserve the operator's input, and show the
// error inline.
func TestHostCreate_InlineErrorPreservesForm(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "net-inline", Name: "test", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// Submit a duplicate-IP / out-of-CIDR error to exercise the
	// nebula_ips branch. 10.99.99.99 is outside 10.0.0.0/24,
	// which trips validateHostIPForNetwork.
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
	form := url.Values{
		"network_id":      {"net-inline"},
		"name":            {"preserved-name"},
		"nebula_ips":      {"10.99.99.99"}, // outside 10.0.0.0/24
		"role":            {"host"},
		"groups":          {"web, prod"},
		"adv_listen_host": {"0.0.0.0"},
		"_csrf":           {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()

	// Re-rendered the form, not a bare error page.
	if !strings.Contains(body, `name="name"`) || !strings.Contains(body, `name="nebula_ips"`) {
		t.Fatalf("body is not the host_new form:\n%s", body)
	}
	// Submitted values preserved.
	if !strings.Contains(body, `value="preserved-name"`) {
		t.Errorf("body should preserve submitted Name field: missing value=\"preserved-name\"")
	}
	if !strings.Contains(body, `value="10.99.99.99"`) {
		t.Errorf("body should preserve submitted nebula_ips field")
	}
	if !strings.Contains(body, `value="web, prod"`) {
		t.Errorf("body should preserve submitted groups field")
	}
	// Selected network is sticky — option for net-inline must carry the
	// `selected` attribute, with any other attributes (data-cidr, …)
	// allowed between value and selected.
	if !hasSelectedOption(body, "net-inline") {
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
		ID: "net-role", Name: "n", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
	form := url.Values{
		"network_id": {"net-role"},
		"name":       {"lh-1"},
		"nebula_ips": {"10.0.0.5"},
		"role":       {"lighthouse"}, // requires public_ip + listen_port → fails
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
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := rec.Body.String()
	if !hasSelectedOption(body, "lighthouse") {
		t.Errorf("body should preserve selected role=lighthouse:\n%s", body)
	}
	if !strings.Contains(body, "public_ip") {
		t.Errorf("body should explain why the form failed; missing the word 'public_ip'")
	}
}

// TestNetworkCreate_InlineErrorPreservesForm — issue #91 for the network
// create form (which lives expanded on /ui/networks).
func TestNetworkCreate_InlineErrorPreservesForm(t *testing.T) {
	w, s := newTestWeb(t)
	seedActiveCA(t, s, "ca-1", "admin-test-id", "seed-ca")
	cookies := loginSession(t, w)

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/networks", cookies)
	form := url.Values{
		"name":  {"prod-net"},
		"cidrs": {"not-a-cidr"},
		"_csrf": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
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
		t.Errorf("body should preserve submitted CIDRs")
	}
	if !strings.Contains(body, `role="alert"`) {
		t.Errorf("body should render alert banner")
	}
	if !strings.Contains(body, `not a valid CIDR`) {
		t.Errorf("body should contain the actual error explanation; got:\n%s", body)
	}
	if strings.Contains(body, "ParsePrefix") {
		t.Errorf("body must not leak the stdlib ParsePrefix text; got:\n%s", body)
	}
	// The create form should not be hidden on validation error.
	if strings.Contains(body, `id="new-network" class="card" style="display:none"`) {
		t.Errorf("create form should be visible (not display:none) on validation error")
	}
}

func TestNetworkCreate_InlineErrorRequiredFields(t *testing.T) {
	w, s := newTestWeb(t)
	seedActiveCA(t, s, "ca-1", "admin-test-id", "seed-ca")
	cookies := loginSession(t, w)

	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/networks", cookies)
	form := url.Values{
		"name":  {""},
		"_csrf": {csrfToken},
		// cidrs is empty array, which is required error
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `name and at least one CIDR are required`) {
		t.Errorf("body should explain missing fields; got:\n%s", rec.Body.String())
	}
}
