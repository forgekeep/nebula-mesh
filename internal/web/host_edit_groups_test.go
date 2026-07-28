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

// seedHostWithGroups creates a network and one enrolled host carrying groups.
func seedHostWithGroups(t *testing.T, s store.Store, groups []string) {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateNetwork(ctx, &models.Network{
		ID: "n-1", Name: "test-net", CIDRs: []string{"192.168.100.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateHost(ctx, &models.Host{
		ID: "h-1", NetworkID: "n-1", Name: "web-1",
		NebulaIPs: []string{"192.168.100.10"},
		Groups:    groups,
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
}

// postHostEditGroups submits the host edit form with everything unchanged
// except the groups field.
func postHostEditGroups(t *testing.T, w *Web, cookies []*http.Cookie, groups string) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/h-1/edit", cookies)
	form := url.Values{
		"network_id": {"n-1"},
		"name":       {"web-1"},
		"nebula_ips": {"192.168.100.10"},
		"groups":     {groups},
		"role":       {"host"},
		"_csrf":      {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/h-1/edit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updatedCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec
}

// TestHostUpdate_POST_GroupChangeSetsPendingRekey: the UI edit form has its
// own copy of the cert-bound-field check, so it needs its own guard — a group
// edit made here must schedule a re-issuance exactly as the API PATCH does.
// Groups ride in the certificate and firewall rules select by group, so until
// the cert is replaced the edit changes nothing on the mesh.
func TestHostUpdate_POST_GroupChangeSetsPendingRekey(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{"web"})

	if rec := postHostEditGroups(t, w, cookies, "web, prod"); rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}

	updated, err := s.GetHost(context.Background(), "h-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(updated.Groups, ","); got != "web,prod" {
		t.Errorf("Groups = %q, want %q", got, "web,prod")
	}
	if !updated.PendingRekey {
		t.Error("PendingRekey should be true after a group change")
	}
}

// TestHostUpdate_POST_GroupRemovalSetsPendingRekey covers the direction that
// matters for access control: a host dropped from a group keeps that group's
// access until its certificate stops claiming membership.
func TestHostUpdate_POST_GroupRemovalSetsPendingRekey(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{"admin", "web"})

	if rec := postHostEditGroups(t, w, cookies, "web"); rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}

	updated, err := s.GetHost(context.Background(), "h-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(updated.Groups, ","); got != "web" {
		t.Errorf("Groups = %q, want %q", got, "web")
	}
	if !updated.PendingRekey {
		t.Error("PendingRekey should be true after a group removal")
	}
}

// TestHostUpdate_POST_UnchangedGroupsDoesNotRekey: resubmitting the form
// untouched must stay idempotent rather than churning the fleet's certs.
func TestHostUpdate_POST_UnchangedGroupsDoesNotRekey(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{"web"})

	if rec := postHostEditGroups(t, w, cookies, "web"); rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}

	updated, err := s.GetHost(context.Background(), "h-1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.PendingRekey {
		t.Error("resubmitting identical groups must not schedule a rekey")
	}
}
