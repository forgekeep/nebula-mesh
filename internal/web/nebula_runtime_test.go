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

func TestNewNebulaRuntimeView(t *testing.T) {
	tests := []struct {
		name      string
		host      *models.Host
		known     bool
		version   string
		source    string
		supported bool
	}{
		{"nil host", nil, false, "", "", false},
		{"unknown", &models.Host{}, false, "", "", false},
		{"agent", &models.Host{NebulaVersion: "1.12.0", Advanced: &models.HostAdvanced{NebulaVersion: "1.11.2"}}, true, "1.12.0", "reported by agent", true},
		{"operator", &models.Host{Advanced: &models.HostAdvanced{NebulaVersion: "v1.11.2"}}, true, "1.11.2", "set by operator", true},
		{"below minimum", &models.Host{NebulaVersion: "1.9.4"}, true, "1.9.4", "reported by agent", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newNebulaRuntimeView(tt.host)
			if got.Known != tt.known || got.Version != tt.version || got.SourceLabel != tt.source || got.Supported != tt.supported {
				t.Errorf("view = %+v", got)
			}
		})
	}
}

func getHostDetail(t *testing.T, w *Web, cookies []*http.Cookie, id string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/ui/hosts/"+id, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("host detail: status = %d", rec.Code)
	}
	return rec.Body.String()
}

func TestHostViews_ShowReportedNebulaRuntime(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{})
	if _, err := s.ReportHostNebulaRuntime(context.Background(), "h-1", "1.12.0", "linux",
		time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}

	list := getHostsList(t, w, cookies)
	if !strings.Contains(list, "<th>Nebula</th>") || !strings.Contains(list, `<span title="reported by agent">1.12.0</span>`) {
		t.Errorf("host list does not show the reported version:\n%s", list)
	}

	detail := getHostDetail(t, w, cookies, "h-1")
	for _, want := range []string{"1.12.0 (reported by agent)", "<td>linux</td>", "2026-10-30 12:00 UTC"} {
		if !strings.Contains(detail, want) {
			t.Errorf("host detail missing %q", want)
		}
	}
}

func TestHostDetail_UnknownNebulaVersionExplainsConservativeConfig(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{})
	detail := getHostDetail(t, w, cookies, "h-1")
	if !strings.Contains(detail, "unknown — the host gets the conservative config") {
		t.Errorf("host detail does not explain the unknown version")
	}
}

func postHostEditNebulaVersion(t *testing.T, w *Web, cookies []*http.Cookie, version string) *httptest.ResponseRecorder {
	t.Helper()
	csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts/h-1/edit", cookies)
	form := url.Values{
		"network_id":         {"n-1"},
		"name":               {"web-1"},
		"nebula_ips":         {"192.168.100.10"},
		"role":               {"host"},
		"adv_nebula_version": {version},
		"_csrf":              {csrfToken},
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

func TestHostUpdate_OperatorNebulaVersion(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)
	seedHostWithGroups(t, s, []string{})

	rec := postHostEditNebulaVersion(t, w, cookies, "latest")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid version: status = %d, want 400", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "advanced.nebula_version must be a Nebula release") || !strings.Contains(body, `value="latest"`) {
		t.Errorf("invalid version: body lacks the error or the submitted value")
	}

	if rec := postHostEditNebulaVersion(t, w, cookies, "1.11.2"); rec.Code != http.StatusSeeOther {
		t.Fatalf("valid version: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	host, err := s.GetHost(context.Background(), "h-1")
	if err != nil {
		t.Fatal(err)
	}
	if host.Advanced == nil || host.Advanced.NebulaVersion != "1.11.2" {
		t.Fatalf("advanced = %+v, want nebula_version 1.11.2", host.Advanced)
	}
	if detail := getHostDetail(t, w, cookies, "h-1"); !strings.Contains(detail, "1.11.2 (set by operator)") {
		t.Errorf("host detail does not show the operator version")
	}
}
