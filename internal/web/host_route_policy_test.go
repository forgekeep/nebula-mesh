package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

// SEC-TENANT-001: the Web inventory includes mutations and uses a valid
// session and CSRF token so CSRF cannot mask the tenant decision.
func TestWebOperatorHostRoutesDenyForeignScope(t *testing.T) {
	const prefix = "/ui/hosts/{id}"
	classified := map[string]int{
		"GET " + prefix: http.StatusForbidden, "GET " + prefix + "/edit": http.StatusForbidden,
		"POST " + prefix + "/edit": http.StatusForbidden, "POST " + prefix + "/mobile-bundle/generate": http.StatusForbidden,
		"POST " + prefix + "/block": http.StatusForbidden, "POST " + prefix + "/clear-restart-pending": http.StatusForbidden,
		"DELETE " + prefix: http.StatusForbidden,
	}
	w, s := newSettingsWeb(t)
	foreign, id, _ := twoTenants(t, w, s)
	csrf, cookies := getCSRFTokenFromCookies(t, w, "/ui/login", []*http.Cookie{foreign})
	before, err := s.GetHost(t.Context(), id)
	require.NoError(t, err)
	version, err := s.GetNetworkConfigVersion(t.Context(), before.NetworkID)
	require.NoError(t, err)
	require.NoError(t, chi.Walk(w.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if route != prefix && !strings.HasPrefix(route, prefix+"/") {
			return nil
		}
		key := method + " " + route
		t.Run(key, func(t *testing.T) {
			want, ok := classified[key]
			require.True(t, ok, "declare the route scope and regression expectation")
			req := httptest.NewRequest(method, strings.Replace(route, "{id}", id, 1), nil)
			req.Header.Set("X-CSRF-Token", csrf)
			for _, cookie := range cookies {
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()
			w.ServeHTTP(rec, req)
			require.Equal(t, want, rec.Code)
			require.NotContains(t, rec.Body.String(), before.Name)
			after, err := s.GetHost(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, before, after)
			actual, err := s.GetNetworkConfigVersion(t.Context(), before.NetworkID)
			require.NoError(t, err)
			require.Equal(t, version, actual)
		})
		delete(classified, key)
		return nil
	}))
	require.Empty(t, classified, "remove obsolete route cases")
}
