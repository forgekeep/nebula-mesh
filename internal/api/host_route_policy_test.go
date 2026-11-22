package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

// SEC-TENANT-001: classified read and mutation routes must deny foreign
// access. Walking the live router makes an unclassified new endpoint fail.
func TestOperatorHostRoutesDenyForeignScope(t *testing.T) {
	const prefix = "/api/v1/hosts/{id}"
	classified := map[string]int{
		"GET " + prefix: http.StatusForbidden, "PATCH " + prefix: http.StatusForbidden,
		"DELETE " + prefix: http.StatusForbidden, "POST " + prefix + "/block": http.StatusForbidden,
		"POST " + prefix + "/unblock": http.StatusForbidden, "POST " + prefix + "/enrollment-token": http.StatusForbidden,
		"POST " + prefix + "/rotate-cert": http.StatusForbidden, "POST " + prefix + "/reenroll": http.StatusForbidden,
		"POST " + prefix + "/mobile-bundle": http.StatusForbidden,
	}
	srv, st := newTestServer(t)
	foreign, _, _ := createOperatorWithCA(t, srv)
	_, _, ownCA := createOperatorWithCA(t, srv)
	netID, id := seedNetworkAndHost(t, st, ownCA.ID, "route-scope-marker", "10.20.0.0/24", "10.20.0.10")
	before, err := st.GetHost(t.Context(), id)
	require.NoError(t, err)
	version, err := st.GetNetworkConfigVersion(t.Context(), netID)
	require.NoError(t, err)
	require.NoError(t, chi.Walk(srv.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if route != prefix && !strings.HasPrefix(route, prefix+"/") {
			return nil
		}
		key := method + " " + route
		t.Run(key, func(t *testing.T) {
			want, ok := classified[key]
			require.True(t, ok, "declare the route scope and regression expectation")
			req := httptest.NewRequest(method, strings.Replace(route, "{id}", id, 1), strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+foreign)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			require.Equal(t, want, rec.Code)
			require.NotContains(t, rec.Body.String(), before.Name)
			after, err := st.GetHost(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, before, after)
			actual, err := st.GetNetworkConfigVersion(t.Context(), netID)
			require.NoError(t, err)
			require.Equal(t, version, actual)
		})
		delete(classified, key)
		return nil
	}))
	require.Empty(t, classified, "remove obsolete route cases")
}
