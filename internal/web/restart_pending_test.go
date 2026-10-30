package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

func postClearRestart(t *testing.T, w *Web, host, tokenPage string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	token, updated := getCSRFTokenFromCookies(t, w, tokenPage, cookies)
	req := httptest.NewRequest(http.MethodPost, "/ui/hosts/"+host+"/clear-restart-pending", strings.NewReader("_csrf="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range updated {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec
}

func TestHostDetail_RestartPendingShownAndCleared(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{})
	ctx := context.Background()

	if detail := getHostDetail(t, w, cookies, "h-1"); strings.Contains(detail, "Mark as restarted") {
		t.Error("host page offers the clear with nothing pending")
	}
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	if _, err := s.SetHostNebulaRestartPending(ctx, "h-1", true, at); err != nil {
		t.Fatal(err)
	}
	detail := getHostDetail(t, w, cookies, "h-1")
	if !strings.Contains(detail, "needed since 2026-10-30 12:00 UTC") || !strings.Contains(detail, "Mark as restarted") {
		t.Errorf("host page does not show the pending restart:\n%s", detail)
	}

	if rec := postClearRestart(t, w, "h-1", "/ui/hosts/h-1", cookies); rec.Code != http.StatusSeeOther {
		t.Fatalf("clear: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	host, err := s.GetHost(ctx, "h-1")
	if err != nil {
		t.Fatal(err)
	}
	if host.NebulaRestartPendingAt != nil {
		t.Error("restart pending not cleared")
	}
	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		found = found || (e.Action == "host.nebula_restart_pending.changed" && e.Resource == "h-1")
	}
	if !found {
		t.Error("operator clear not audited")
	}
}

// SEC-TENANT-001: a non-owner cannot clear another tenant's restart mark.
func TestHostClearRestartPending_SEC_TENANT_001_NonOwnerForbidden(t *testing.T) {
	w, s := newSettingsWeb(t)
	bob, foreignHost, ownHost := twoTenants(t, w, s)
	ctx := context.Background()
	if _, err := s.SetHostNebulaRestartPending(ctx, foreignHost, true, time.Now()); err != nil {
		t.Fatal(err)
	}

	rec := postClearRestart(t, w, foreignHost, "/ui/hosts/"+ownHost, []*http.Cookie{bob})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	got, err := s.GetHost(ctx, foreignHost)
	if err != nil {
		t.Fatal(err)
	}
	if got.NebulaRestartPendingAt == nil {
		t.Error("foreign host's mark was cleared despite the 403")
	}
}
