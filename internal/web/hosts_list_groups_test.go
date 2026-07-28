package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// getHostsList performs an authenticated GET of the host list page.
func getHostsList(t *testing.T, w *Web, cookies []*http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/hosts", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("hosts list: status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// TestHostsList_ShowsGroups: group membership drives firewall policy, so the
// host list is where an operator needs to see it — otherwise checking which
// hosts hold which groups means opening every host in turn.
func TestHostsList_ShowsGroups(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{"admin", "web"})

	body := getHostsList(t, w, cookies)

	if !strings.Contains(body, "<th>Groups</th>") {
		t.Error("host list is missing the Groups column header")
	}
	if !strings.Contains(body, "admin, web") {
		t.Error("host list does not render the host's groups")
	}
}

// TestHostsList_GroupsEmptyPlaceholder keeps a host with no groups from
// rendering a blank cell that reads as a broken column.
func TestHostsList_GroupsEmptyPlaceholder(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{})

	body := getHostsList(t, w, cookies)

	if !strings.Contains(body, `<td class="host-groups">—</td>`) {
		t.Error("a host with no groups should render the em-dash placeholder")
	}
}
