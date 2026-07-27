package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// patchHostGroups PATCHes a host's groups and returns the decoded response.
func patchHostGroups(t *testing.T, srv *Server, hostID string, groups []string) *models.Host {
	t.Helper()
	body, err := json.Marshal(updateHostRequest{Groups: &groups})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/hosts/"+hostID, bytes.NewBuffer(body))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "PATCH groups: %s", rec.Body.String())

	var updated models.Host
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&updated))
	return &updated
}

// certGroups parses a stored certificate PEM and returns its embedded groups.
func certGroups(t *testing.T, pemBytes []byte) []string {
	t.Helper()
	parsed, _, err := cert.UnmarshalCertificateFromPEM(pemBytes)
	require.NoError(t, err)
	return parsed.Groups()
}

// TestUpdateHost_GroupChangeSetsPendingRekey: a host's groups are baked into
// its Nebula certificate, and firewall rules select peers by group. Changing
// the groups on the host row therefore has no effect on the mesh until a new
// certificate is issued — so the change has to schedule one, exactly as a
// rename or an IP change does.
func TestUpdateHost_GroupChangeSetsPendingRekey(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	fresh, err := srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.False(t, fresh.PendingRekey, "setup: PendingRekey should start false")

	updated := patchHostGroups(t, srv, host.ID, []string{"web", "prod"})
	require.Equal(t, []string{"web", "prod"}, updated.Groups)
	require.True(t, updated.PendingRekey, "changing groups must schedule a new certificate")

	fresh, err = srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.True(t, fresh.PendingRekey, "the scheduled rekey must be persisted")
}

// TestUpdateHost_GroupRemovalSetsPendingRekey is the security-relevant
// direction: dropping a host from a privileged group must not leave it holding
// a certificate that still claims membership. Peers authorize on the cert, not
// on the server's host row.
func TestUpdateHost_GroupRemovalSetsPendingRekey(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	_ = patchHostGroups(t, srv, host.ID, []string{"admin", "web"})
	require.NoError(t, srv.store.ClearPendingRekey(context.Background(), host.ID))

	updated := patchHostGroups(t, srv, host.ID, []string{"web"})
	require.Equal(t, []string{"web"}, updated.Groups)
	require.True(t, updated.PendingRekey, "removing a group must schedule a new certificate")
}

// TestUpdateHost_SameGroupsDoesNotRekey: a PATCH that does not actually change
// the groups must stay a no-op. Re-issuing on every write would churn
// certificates across the fleet for idempotent config pushes.
func TestUpdateHost_SameGroupsDoesNotRekey(t *testing.T) {
	srv, _ := newTestServer(t)
	netID := createNetwork(t, srv)
	host := createHostHelper(t, srv, netID, "web-1", "192.168.100.1", nil)

	_ = patchHostGroups(t, srv, host.ID, []string{"web"})
	require.NoError(t, srv.store.ClearPendingRekey(context.Background(), host.ID))

	updated := patchHostGroups(t, srv, host.ID, []string{"web"})
	require.False(t, updated.PendingRekey, "re-sending identical groups must not rekey")

	fresh, err := srv.store.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	require.False(t, fresh.PendingRekey, "re-sending identical groups must not rekey")
}

// TestUpdateHost_GroupChangeReachesTheAgent walks the whole chain the bug
// report was about: an operator edits the groups, and the host's very next
// signed poll is told to re-key. Everything else here asserts one link;
// without this one, all the links could pass while the chain stays broken.
func TestUpdateHost_GroupChangeReachesTheAgent(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	host, err := st.GetHostByFingerprint(context.Background(), agent.fingerprint)
	require.NoError(t, err)
	require.False(t, host.PendingRekey, "setup: nothing pending before the edit")

	_ = patchHostGroups(t, srv, host.ID, []string{"admin"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "poll: %s", rec.Body.String())

	var resp agentUpdatesResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.True(t, resp.RekeyRequired, "the agent was never told to re-key after the group change")
	require.NotEmpty(t, resp.EnrollmentToken, "a re-key needs a token for the agent to re-enroll with")
}

// TestUpdateHost_GroupChangeReissuedCertCarriesNewGroups closes the loop on
// why the rekey matters: once the scheduled re-issuance happens, the new
// certificate must carry the new groups and drop the old ones.
func TestUpdateHost_GroupChangeReissuedCertCarriesNewGroups(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	host, err := st.GetHostByFingerprint(context.Background(), agent.fingerprint)
	require.NoError(t, err)

	_ = patchHostGroups(t, srv, host.ID, []string{"admin"})
	certInfo, err := st.GetCertificateInfo(context.Background(), host.ID)
	require.NoError(t, err)
	require.NotContains(t, certGroups(t, []byte(certInfo.PEM)), "admin",
		"setup: the cert on record predates the group change")

	// Re-issue the way the rekey path eventually does: same key, current
	// host attributes.
	host, err = st.GetHost(context.Background(), host.ID)
	require.NoError(t, err)
	signed, err := srv.signHostCert(context.Background(), host, certInfo, srv.now())
	require.NoError(t, err)

	require.Equal(t, []string{"admin"}, certGroups(t, signed.certPEM),
		"the re-issued certificate must carry the host's current groups")
}
