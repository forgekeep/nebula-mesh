package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func postHostEditTuning(t *testing.T, w *Web, cookies []*http.Cookie, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/h-1/edit", cookies)
	form := url.Values{
		"network_id": {"n-1"},
		"name":       {"web-1"},
		"nebula_ips": {"192.168.100.10"},
		"role":       {"host"},
		"_csrf":      {csrfToken},
	}
	for k, v := range extra {
		form[k] = v
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

func TestHostUpdate_TuningFollowsReportedRuntime(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{})
	if _, err := s.ReportHostNebulaRuntime(context.Background(), "h-1", "1.11.2", "linux", time.Now()); err != nil {
		t.Fatal(err)
	}

	rec := postHostEditTuning(t, w, cookies, url.Values{"adv_udp_offloads": {"true"}})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "requires Nebula 1.12.0 or newer; host runs 1.11.2") {
		t.Fatalf("offloads on 1.11: %d", rec.Code)
	}

	rec = postHostEditTuning(t, w, cookies, url.Values{
		"adv_routines": {"4"}, "adv_pin_threads": {"false"}, "adv_cpu_affinity": {"0, 2"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("pinning on 1.11: status = %d, want 400", rec.Code)
	}

	if rec := postHostEditTuning(t, w, cookies, url.Values{"adv_routines": {"4"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("routines on 1.11: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	host, _ := s.GetHost(context.Background(), "h-1")
	if host.Advanced == nil || host.Advanced.Routines != 4 {
		t.Fatalf("advanced = %+v, want routines 4", host.Advanced)
	}
}

func TestHostDetail_ListsUnappliedTuning(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{})
	// Saved while the version was unknown, so validation let it through.
	if rec := postHostEditTuning(t, w, cookies, url.Values{"adv_udp_offloads": {"true"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	detail := getHostDetail(t, w, cookies, "h-1")
	if !strings.Contains(detail, "<code>advanced.udp_offloads</code> — UDP and tun offloads requires Nebula 1.12.0 or newer; the host&#39;s Nebula version is unknown") {
		t.Errorf("host detail does not list the unapplied override:\n%s", detail)
	}

	edit := getHostEditForm(t, w, cookies)
	if !strings.Contains(edit, `<option value="true" selected>enable</option>`) {
		t.Error("edit form does not keep the saved udp_offloads value")
	}
}

func getHostEditForm(t *testing.T, w *Web, cookies []*http.Cookie) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/h-1/edit", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("edit form: %d", rec.Code)
	}
	return rec.Body.String()
}
