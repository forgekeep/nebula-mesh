package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// SEC-TENANT-001: the API host operations preserve both the response boundary
// and the authorization decision before the revocation write.
func TestOperatorHostReadAndBlockScope(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{
		{"owner", http.StatusOK}, {"admin", http.StatusOK},
		{"foreign", http.StatusForbidden}, {"missing", http.StatusUnauthorized}, {"disabled", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, st := newTestServer(t)
			ownerKey, owner, ca := createOperatorWithCA(t, srv)
			_, id := seedNetworkAndHost(t, st, ca.ID, "scope-marker", "10.10.0.0/24", "10.10.0.10")
			key := ownerKey
			switch tc.name {
			case "admin":
				key = testAPIKey
			case "foreign":
				key, _, _ = createOperatorWithCA(t, srv)
			case "missing":
				key = ""
			case "disabled":
				require.NoError(t, st.DisableOperator(t.Context(), owner.ID))
			}
			path := "/api/v1/hosts/" + id
			for _, request := range []struct{ method, path string }{{http.MethodGet, path}, {http.MethodPost, path + "/block"}} {
				req := httptest.NewRequest(request.method, request.path, nil)
				if key != "" {
					req.Header.Set("Authorization", "Bearer "+key)
				}
				rec := httptest.NewRecorder()
				srv.ServeHTTP(rec, req)
				require.Equal(t, tc.code, rec.Code, request.method)
				if tc.code == http.StatusOK {
					require.Contains(t, rec.Body.String(), "host-scope-marker")
				} else {
					require.NotContains(t, rec.Body.String(), "host-scope-marker")
				}
			}
			got, err := st.GetHost(t.Context(), id)
			require.NoError(t, err)
			want := models.HostStatusPending
			if tc.code == http.StatusOK {
				want = models.HostStatusBlocked
			}
			require.Equal(t, want, got.Status)
		})
	}
}
