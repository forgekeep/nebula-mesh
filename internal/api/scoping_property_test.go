package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// listScoping classifies a registered GET route by its multi-tenant
// read-side behavior. The registry below pairs with two tests:
//
//   - TestProtectedGETRoutesAreClassified walks the live chi router and
//     fails the build if any GET route is missing from the registry. A new
//     list endpoint added without a deliberate scoping decision therefore
//     breaks CI at PR time — which is the point. The cross-operator data
//     leak that GHSA-598g-h2vc-h5vg fixed slipped in precisely because new
//     read paths were not forced to declare their scoping.
//
//   - TestListEndpointsScopeToOwner drives the actual assertions from the
//     same registry, so the exhaustiveness check and the behavioral check
//     never drift apart.
type listScoping int

const (
	// scopedToOwner: a non-admin sees only rows under CAs they own; an
	// admin sees every row. Enforced today by the ListCAsByOwner filter in
	// each handler (hosts.go, networks.go, cas.go).
	scopedToOwner listScoping = iota
	// adminOnly: a non-admin is refused with 403 and no tenant data in the
	// body; an admin gets 200.
	adminOnly
	// singleResource: GET /.../{id}, guarded per-row by canAccess* and
	// covered by the *_authz_test.go batteries and scoping_boundary_test.go.
	// Not exercised by the collection-scoping loop.
	singleResource
	// publicRoute: unauthenticated or non-operator surface (health probes,
	// metrics, agent poll). Not an operator-facing tenant read.
	publicRoute
)

// protectedGETScoping is the single source of truth for the read-side
// multi-tenant behavior of every GET route the API registers. Keep it in
// sync with setupRoutes — TestProtectedGETRoutesAreClassified enforces that.
var protectedGETScoping = map[string]listScoping{
	// Public / non-operator surfaces.
	"/health":               publicRoute,
	"/healthz":              publicRoute,
	"/readyz":               publicRoute,
	"/metrics":              publicRoute,
	"/debug/vars":           publicRoute,
	"/api/v1/agent/updates": publicRoute, // agent poll, signed-poll auth — not operator bearer

	// Collection reads — must scope non-admins to owned CAs.
	"/api/v1/networks":              scopedToOwner,
	"/api/v1/hosts":                 scopedToOwner,
	"/api/v1/cas":                   scopedToOwner,
	"/api/v1/mesh-imports":          scopedToOwner,
	"/api/v1/webhook-subscriptions": scopedToOwner,

	// Admin-only reads — non-admin gets 403, no tenant data in the body.
	"/api/v1/operators":               adminOnly,
	"/api/v1/operators/{id}/api-keys": adminOnly,
	"/api/v1/audit-log":               adminOnly,
	"/api/v1/blocklist":               adminOnly,
	"/api/v1/settings":                adminOnly,

	// Single-resource reads — guarded per-row by canAccess*.
	"/api/v1/networks/{id}":               singleResource,
	"/api/v1/networks/{id}/firewall":      singleResource,
	"/api/v1/networks/{id}/mobile-config": singleResource,
	"/api/v1/hosts/{id}":                  singleResource,
	"/api/v1/cas/{id}":                    singleResource,
	"/api/v1/mesh-imports/{id}":           singleResource,
	"/api/v1/webhook-subscriptions/{id}":  singleResource,
}

// SEC-TENANT-001: TestProtectedGETRoutesAreClassified fails the moment setupRoutes registers
// a GET route that protectedGETScoping does not classify. It is the tripwire
// that forces every future read endpoint to declare its tenant scoping.
func TestProtectedGETRoutesAreClassified(t *testing.T) {
	srv, _ := newTestServer(t)

	var unclassified []string
	err := chi.Walk(srv.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method != http.MethodGet {
			return nil
		}
		if _, ok := protectedGETScoping[route]; !ok {
			unclassified = append(unclassified, route)
		}
		return nil
	})
	require.NoError(t, err)

	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		t.Fatalf("unclassified GET route(s) found by chi.Walk — add each to protectedGETScoping\n"+
			"with its multi-tenant scoping (scopedToOwner / adminOnly / singleResource / publicRoute);\n"+
			"if it returns a collection, it must be scopedToOwner or adminOnly so the leak test below\n"+
			"covers it:\n  %s", strings.Join(unclassified, "\n  "))
	}
}

// SEC-TENANT-001: TestListEndpointsScopeToOwner pins the read-side invariant for every
// collection and admin-only route: operator A never sees operator B's data
// and vice-versa, while an admin sees both. The CA id is used as the leak
// marker because it surfaces in every scoped collection — as ca_id on hosts
// and networks, and as id on the CA itself.
func TestListEndpointsScopeToOwner(t *testing.T) {
	srv, st := newTestServer(t)

	keyA, opA, caA := createOperatorWithCA(t, srv)
	keyB, opB, caB := createOperatorWithCA(t, srv)
	seedCanceledMeshImport(t, st, opA.ID, caA)
	seedCanceledMeshImport(t, st, opB.ID, caB)
	// Distinct CIDRs/IPs so the seed is robust to any nebula_ip uniqueness
	// scheme; ownership is what the test cares about, not addressing.
	seedNetworkAndHost(t, st, caA.ID, "a", "10.10.0.0/24", "10.10.0.10")
	seedNetworkAndHost(t, st, caB.ID, "b", "10.20.0.0/24", "10.20.0.10")
	// Webhook subscriptions carry no ca_id, so embed the owner's CA id in the
	// URL to satisfy the generic owner-leak assertions below.
	seedWebhookSub(t, st, opA.ID, "https://example.com/"+caA.ID)
	seedWebhookSub(t, st, opB.ID, "https://example.com/"+caB.ID)

	for route, scoping := range protectedGETScoping {
		switch scoping {
		case scopedToOwner:
			t.Run("scoped "+route, func(t *testing.T) {
				codeA, bodyA := authedGET(srv, route, keyA)
				assert.Equal(t, http.StatusOK, codeA)
				assert.Contains(t, bodyA, caA.ID, "owner A must see its own resources")
				assert.NotContains(t, bodyA, caB.ID, "owner A must not see operator B's resources")
				assert.NotContains(t, bodyA, srv.defaultCAID, "owner A must not see the admin-owned default CA")

				codeB, bodyB := authedGET(srv, route, keyB)
				assert.Equal(t, http.StatusOK, codeB)
				assert.Contains(t, bodyB, caB.ID, "owner B must see its own resources")
				assert.NotContains(t, bodyB, caA.ID, "owner B must not see operator A's resources")
				assert.NotContains(t, bodyB, srv.defaultCAID, "owner B must not see the admin-owned default CA")

				codeAdmin, bodyAdmin := authedGET(srv, route, testAPIKey)
				assert.Equal(t, http.StatusOK, codeAdmin)
				assert.Contains(t, bodyAdmin, caA.ID, "admin must see operator A's resources")
				assert.Contains(t, bodyAdmin, caB.ID, "admin must see operator B's resources")
			})
		case adminOnly:
			t.Run("admin-only "+route, func(t *testing.T) {
				code, body := authedGET(srv, route, keyA)
				assert.Equal(t, http.StatusForbidden, code, "non-admin must be refused")
				assert.NotContains(t, body, caA.ID, "403 body must not leak tenant data")
				assert.NotContains(t, body, caB.ID, "403 body must not leak tenant data")

				adminCode, _ := authedGET(srv, route, testAPIKey)
				assert.Equal(t, http.StatusOK, adminCode, "admin must be allowed")
			})
		}
	}
}

func seedCanceledMeshImport(t *testing.T, st *store.SQLiteStore, ownerID string, ca *models.CA) {
	t.Helper()
	now := time.Now()
	network := &models.Network{
		ID: uuid.NewString(), Name: "import-marker-" + ca.ID,
		CIDRs: []string{"172.31.0.0/16"}, CAID: ca.ID, CreatedAt: now,
	}
	require.NoError(t, st.CreateNetwork(context.Background(), network))
	item := &models.MeshImport{
		ID: uuid.NewString(), NetworkID: network.ID, CAID: ca.ID, OwnerOperatorID: ownerID,
		Status: models.MeshImportStatusCollecting, TokenHash: uuid.NewString(),
		TokenExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, st.CreateMeshImport(context.Background(), item))
	require.NoError(t, st.CancelMeshImport(context.Background(), item.ID, "scoping fixture", now))
}

// authedGET issues GET against the route as the bearer of key and returns the
// status and body. Route patterns with {id} are bound to the seeded admin
// operator, which exists in every newTestServer.
func authedGET(srv *Server, route, key string) (int, string) {
	req := httptest.NewRequest(http.MethodGet, concretePath(route), nil)
	req.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

// concretePath binds the {id} param in a chi route pattern so the registry
// can be requested directly. Admin-only handlers gate on role before reading
// the id, so the bound value only matters for the admin success case
// (test-admin always exists). Only GET routes reach here, and none carry a
// {kid} sub-key param, so {id} is the only substitution needed.
func concretePath(route string) string {
	return strings.ReplaceAll(route, "{id}", "test-admin")
}

// seedWebhookSub inserts a webhook subscription owned by ownerID directly via
// the store, bypassing the create handler's owner derivation so cross-operator
// fixtures can be set up.
func seedWebhookSub(t *testing.T, st *store.SQLiteStore, ownerID, url string) {
	t.Helper()
	require.NoError(t, st.CreateWebhookSubscription(context.Background(), &models.WebhookSubscription{
		ID:              uuid.New().String(),
		OwnerOperatorID: ownerID,
		URL:             url,
		Active:          true,
		CreatedAt:       time.Now(),
	}))
}

// seedNetworkAndHost inserts a network and a host bound to caID directly via
// the store, bypassing the create handlers (which would re-derive ownership
// from the caller). This lets the scoping tests set up cross-operator
// fixtures that the API would otherwise refuse to create. Returns the network
// and host ids.
func seedNetworkAndHost(t *testing.T, st *store.SQLiteStore, caID, label, cidr, ip string) (netID, hostID string) {
	t.Helper()
	ctx := context.Background()
	netID = uuid.New().String()
	hostID = uuid.New().String()
	require.NoError(t, st.CreateNetwork(ctx, &models.Network{
		ID:        netID,
		Name:      "net-" + label,
		CIDRs:     []string{cidr},
		CAID:      caID,
		CreatedAt: time.Now(),
	}))
	require.NoError(t, st.CreateHost(ctx, &models.Host{
		ID:        hostID,
		NetworkID: netID,
		CAID:      caID,
		Name:      "host-" + label,
		NebulaIPs: []string{ip},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusPending,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}))
	return netID, hostID
}
