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

// TestCreateHostViaUI_RoleReachability mirrors issue #94 — the host create
// form must reject role=lighthouse / role=relay without a non-empty
// public_ip and a non-zero listen_port. Without this, peer config.yml
// silently renders an empty static_host_map and the lighthouse is never
// dialed.
func TestCreateHostViaUI_RoleReachability(t *testing.T) {
	w, s := newTestWeb(t)
	cookies := loginSession(t, w)

	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "net-rr", Name: "test", CIDRs: []string{"10.0.0.0/24"}, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		role       string
		publicIP   string
		listenPort string
		nebulaIP   string
		wantStatus int
		wantSubstr string
	}{
		{
			name:       "lighthouse without public_ip rejected",
			role:       "lighthouse",
			publicIP:   "",
			listenPort: "4242",
			nebulaIP:   "10.0.0.5",
			wantStatus: http.StatusBadRequest,
			wantSubstr: "public_ip",
		},
		{
			name:       "lighthouse without listen_port rejected",
			role:       "lighthouse",
			publicIP:   "203.0.113.1",
			listenPort: "",
			nebulaIP:   "10.0.0.6",
			wantStatus: http.StatusBadRequest,
			wantSubstr: "listen_port",
		},
		{
			name:       "relay without public_ip rejected",
			role:       "relay",
			publicIP:   "",
			listenPort: "4242",
			nebulaIP:   "10.0.0.7",
			wantStatus: http.StatusBadRequest,
			wantSubstr: "public_ip",
		},
		{
			name:       "lighthouse with both fields accepted",
			role:       "lighthouse",
			publicIP:   "203.0.113.2",
			listenPort: "4242",
			nebulaIP:   "10.0.0.8",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			csrfToken, updatedCookies := getCSRFTokenFromCookies(t, w, "/ui/hosts", cookies)
			form := url.Values{
				"network_id":  {"net-rr"},
				"name":        {"h-" + strings.ReplaceAll(tc.name, " ", "-")},
				"nebula_ips":  {tc.nebulaIP},
				"role":        {tc.role},
				"public_ip":   {tc.publicIP},
				"listen_port": {tc.listenPort},
				"_csrf":       {csrfToken},
			}
			req := httptest.NewRequest(http.MethodPost, "/ui/hosts", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for _, c := range updatedCookies {
				req.AddCookie(c)
			}
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body: %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Errorf("body = %q, want substring %q", rec.Body.String(), tc.wantSubstr)
			}
		})
	}
}
