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
)

// createHostViaForm posts the host-create form and returns the recorder, so a
// test can assert on the response of a second, colliding submission.
func createHostViaForm(t *testing.T, w *Web, cookies []*http.Cookie, networkID, name, ip string) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
	form := url.Values{
		"network_id": {networkID},
		"name":       {name},
		"nebula_ips": {ip},
		"role":       {"host"},
		"_csrf":      {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec
}

// TestHostCreate_DuplicateNameRendersInlineError reproduces the production
// failure behind issue "cannot add a new host": reusing a host name already
// present in the network returned a bare 500 "Failed to create host" with no
// hint of the cause, so an operator could not tell an input mistake from a
// server outage. A duplicate name is form input, so it must come back through
// the same inline-error path as every other field: 400, the form re-rendered
// with the submitted values, and a message naming the collision.
func TestHostCreate_DuplicateNameRendersInlineError(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-dup", Name: "n", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	if rec := createHostViaForm(t, w, cookies, "n-dup", "blai", "10.0.0.10"); rec.Code != http.StatusOK {
		t.Fatalf("first create: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	rec := createHostViaForm(t, w, cookies, "n-dup", "blai", "10.0.0.11")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate name: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "Failed to create host") {
		t.Errorf("body must not fall through to the generic failure text; got:\n%s", body)
	}
	if !strings.Contains(body, "blai") || !strings.Contains(body, "already exists") {
		t.Errorf("body should name the colliding host and say it already exists; got:\n%s", body)
	}
	// The form must come back populated so the operator can correct the name
	// without retyping the rest.
	if !strings.Contains(body, `value="10.0.0.11"`) {
		t.Errorf("submitted nebula_ip should be preserved in the re-rendered form; got:\n%s", body)
	}
}

// TestHostCreate_SameNameDifferentNetworkSucceeds guards against the fix
// over-reaching: names are unique per network, not globally.
func TestHostCreate_SameNameDifferentNetworkSucceeds(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	ctx := context.Background()
	for _, n := range []*models.Network{
		{ID: "n-one", Name: "one", CIDRs: []string{"10.1.0.0/24"}, CreatedAt: time.Now()},
		{ID: "n-two", Name: "two", CIDRs: []string{"10.2.0.0/24"}, CreatedAt: time.Now()},
	} {
		if err := s.CreateNetwork(ctx, n); err != nil {
			t.Fatal(err)
		}
	}

	if rec := createHostViaForm(t, w, cookies, "n-one", "shared", "10.1.0.10"); rec.Code != http.StatusOK {
		t.Fatalf("create in first network: status = %d; body=%s", rec.Code, rec.Body.String())
	}
	if rec := createHostViaForm(t, w, cookies, "n-two", "shared", "10.2.0.10"); rec.Code != http.StatusOK {
		t.Errorf("same name in another network must succeed: status = %d; body=%s", rec.Code, rec.Body.String())
	}
}

// seedHost inserts a host directly, bypassing the form, so a rename test can
// set up the collision without depending on the create path.
func seedHost(t *testing.T, s hostSeeder, id, networkID, name, ip string) {
	t.Helper()
	if err := s.CreateHost(context.Background(), &models.Host{
		ID:        id,
		NetworkID: networkID,
		Name:      name,
		NebulaIPs: []string{ip},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

type hostSeeder interface {
	CreateHost(ctx context.Context, h *models.Host) error
}

// renameHostViaForm submits the host edit form with a new name.
func renameHostViaForm(t *testing.T, w *Web, cookies []*http.Cookie, hostID, networkID, name, ip string) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/"+hostID+"/edit", cookies)
	form := url.Values{
		"network_id": {networkID},
		"name":       {name},
		"nebula_ips": {ip},
		"role":       {"host"},
		"_csrf":      {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/"+hostID+"/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec
}

// TestHostUpdate_POST_DuplicateName is the rename counterpart of the create
// test: renaming onto a taken name must re-render the edit form with the
// reason rather than emitting a bare 500 "Failed to update host".
func TestHostUpdate_POST_DuplicateName(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-ren", Name: "n", CIDRs: []string{"10.5.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	seedHost(t, s, "h-keep", "n-ren", "tauro", "10.5.0.10")
	seedHost(t, s, "h-move", "n-ren", "agricer", "10.5.0.11")

	rec := renameHostViaForm(t, w, cookies, "h-move", "n-ren", "tauro", "10.5.0.11")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("rename onto a taken name: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "Failed to update host") {
		t.Errorf("body must not fall through to the generic failure text; got:\n%s", body)
	}
	if !strings.Contains(body, "tauro") || !strings.Contains(body, "already exists") {
		t.Errorf("body should name the colliding host and say it already exists; got:\n%s", body)
	}
}

// TestHostUpdate_POST_RenameToOwnNameSucceeds guards the self-exclusion on the
// web path: an edit that leaves the name alone must still save.
func TestHostUpdate_POST_RenameToOwnNameSucceeds(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n-self", Name: "n", CIDRs: []string{"10.6.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	seedHost(t, s, "h-self", "n-self", "isis", "10.6.0.10")

	rec := renameHostViaForm(t, w, cookies, "h-self", "n-self", "isis", "10.6.0.10")
	if rec.Code != http.StatusSeeOther {
		t.Errorf("keeping its own name: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
}
