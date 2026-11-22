package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// SEC-TENANT-001: the Web adapter keeps authentication and CSRF while applying
// the same host read and block policy as the JSON API.
func TestWebOperatorHostReadAndBlockScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{
		{"owner", http.StatusOK}, {"admin", http.StatusOK},
		{"foreign", http.StatusForbidden}, {"missing", http.StatusSeeOther}, {"disabled", http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, s := newSettingsWeb(t)
			owner := authedSession(t, s, "scope-owner", models.OperatorRoleUser)
			_, _, id := seedTenant(t, s, "op-scope-owner", "scope-marker")
			path := "/ui/hosts/" + id
			var session = owner
			switch tc.name {
			case "admin":
				session = authedSession(t, s, "scope-admin", models.OperatorRoleAdmin)
			case "foreign":
				session = authedSession(t, s, "scope-foreign", models.OperatorRoleUser)
			case "missing":
				session = nil
			}
			var cookies []*http.Cookie
			if session != nil {
				cookies = append(cookies, session)
			}
			csrf, cookies := getCSRFTokenFromCookies(t, w, "/ui/login", cookies)
			if tc.name == "disabled" {
				require.NoError(t, s.DisableOperator(t.Context(), "op-scope-owner"))
			}
			for _, request := range []struct{ method, path string }{{http.MethodGet, path}, {http.MethodPost, path + "/block"}} {
				req := httptest.NewRequest(request.method, request.path, nil)
				req.Header.Set("X-CSRF-Token", csrf)
				for _, cookie := range cookies {
					req.AddCookie(cookie)
				}
				rec := httptest.NewRecorder()
				w.ServeHTTP(rec, req)
				require.Equal(t, tc.code, rec.Code, request.method)
				if tc.code != http.StatusOK {
					require.NotContains(t, rec.Body.String(), "host-scope-marker")
				} else if request.method == http.MethodGet {
					require.Contains(t, rec.Body.String(), "host-scope-marker")
				} else {
					require.Equal(t, "/ui/hosts", rec.Header().Get("HX-Redirect"))
				}
			}
			got, err := s.GetHost(t.Context(), id)
			require.NoError(t, err)
			want := models.HostStatusPending
			if tc.code == http.StatusOK {
				want = models.HostStatusBlocked
			}
			require.Equal(t, want, got.Status)
		})
	}
}
