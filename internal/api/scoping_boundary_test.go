package api

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestListHosts_ForeignNetworkFilterDoesNotBypassScoping pins that a
// non-admin cannot exfiltrate another operator's hosts by passing the
// foreign network's id as the ?network_id= filter. The filter runs in the
// store query, but the owned-CA scoping in handleListHosts runs afterwards
// (hosts.go:190), so the result must stay empty for B even when the filter
// matches A's hosts.
func TestListHosts_ForeignNetworkFilterDoesNotBypassScoping(t *testing.T) {
	srv, st := newTestServer(t)
	keyA, _, caA := createOperatorWithCA(t, srv)
	keyB, _, _ := createOperatorWithCA(t, srv)
	netA, _ := seedNetworkAndHost(t, st, caA.ID, "a", "10.10.0.0/24", "10.10.0.10")

	// B aims the filter at A's network.
	codeB, bodyB := authedGET(srv, "/api/v1/hosts?network_id="+netA, keyB)
	assert.Equal(t, http.StatusOK, codeB)
	assert.NotContains(t, bodyB, caA.ID, "filter must not let B read A's hosts")
	assert.NotContains(t, bodyB, "host-a")

	// Sanity: the filter itself works for the owner — A sees the host when
	// it scopes to A's own network. This proves the empty result for B is
	// the scoping, not a broken filter.
	codeA, bodyA := authedGET(srv, "/api/v1/hosts?network_id="+netA, keyA)
	assert.Equal(t, http.StatusOK, codeA)
	assert.Contains(t, bodyA, caA.ID)
	assert.Contains(t, bodyA, "host-a")
}

// TestListOperators_NonAdminForbiddenBody pins that a non-admin is refused
// with the role-required error and, crucially, that the 403 body does not
// enumerate operators. The CA-id leak marker used by the property harness
// does not apply here (operators carry no ca_id), so the operator username is
// the marker: it must never appear in the refusal body.
func TestListOperators_NonAdminForbiddenBody(t *testing.T) {
	srv, _ := newTestServer(t)
	keyA, opA, _ := createOperatorWithCA(t, srv)

	code, body := authedGET(srv, "/api/v1/operators", keyA)
	assert.Equal(t, http.StatusForbidden, code)
	assert.Contains(t, body, "operator management requires the admin role")
	assert.NotContains(t, body, opA.Username, "403 body must not enumerate operators")
}

// TestGetHost_NonOwnerDoesNotLeakBody pins the security-critical invariant on
// the single-host read: a non-owner never receives the host body, whether the
// host exists-but-is-foreign or does not exist at all.
//
// Note the existence side-channel that remains: a foreign-but-existing host
// returns 403 while a missing id returns 404, so the status code distinguishes
// existence. That split is systemic across the by-id host handlers (get,
// delete, block, unblock, rotate-cert, reenroll, update — all GetHost→404 then
// canAccessHost→403). Collapsing it to a uniform 404 is a behavior change for
// a separate PR, so this test deliberately asserts the non-leak invariant
// rather than pinning the 403/404 split — a future uniform-404 hardening must
// not have to fight this test.
func TestGetHost_NonOwnerDoesNotLeakBody(t *testing.T) {
	srv, st := newTestServer(t)
	_, _, caA := createOperatorWithCA(t, srv)
	keyB, _, _ := createOperatorWithCA(t, srv)
	_, hostA := seedNetworkAndHost(t, st, caA.ID, "a", "10.10.0.0/24", "10.10.0.10")

	foreignCode, foreignBody := authedGET(srv, "/api/v1/hosts/"+hostA, keyB)
	missingCode, missingBody := authedGET(srv, "/api/v1/hosts/does-not-exist", keyB)
	t.Logf("by-id existence side-channel: foreign-existing=%d missing=%d", foreignCode, missingCode)

	for _, c := range []struct {
		name string
		code int
		body string
	}{
		{"foreign-existing", foreignCode, foreignBody},
		{"missing", missingCode, missingBody},
	} {
		assert.NotEqual(t, http.StatusOK, c.code, "%s: non-owner must never get 200", c.name)
		assert.NotContains(t, c.body, caA.ID, "%s: host body must not leak", c.name)
		assert.NotContains(t, c.body, "host-a", "%s: host body must not leak", c.name)
	}
}

// TestGetByID_NonOwnerDoesNotLeak extends the single-host non-leak guarantee
// to the other singleResource by-id reads — network, firewall, and CA. The
// property harness only drives the collection routes, so without this the
// GHSA-598g cross-operator boundary for these endpoints would rest entirely
// on the pre-existing *_authz_test.go batteries. Pinning it here keeps the
// whole read-side boundary in one place: a regression that inverted an
// ownership comparison in canAccessNetwork / the CA gate is caught by this PR.
func TestGetByID_NonOwnerDoesNotLeak(t *testing.T) {
	srv, st := newTestServer(t)
	_, _, caA := createOperatorWithCA(t, srv)
	keyB, _, _ := createOperatorWithCA(t, srv)
	netA, _ := seedNetworkAndHost(t, st, caA.ID, "a", "10.10.0.0/24", "10.10.0.10")

	for _, c := range []struct{ name, path string }{
		{"network-by-id", "/api/v1/networks/" + netA},
		{"network-firewall", "/api/v1/networks/" + netA + "/firewall"},
		{"ca-by-id", "/api/v1/cas/" + caA.ID},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, body := authedGET(srv, c.path, keyB)
			assert.NotEqual(t, http.StatusOK, code, "non-owner must never get 200")
			assert.NotContains(t, body, caA.ID, "non-owner must not receive owner's resource")
		})
	}
}
