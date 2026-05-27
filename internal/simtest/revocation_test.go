package simtest

import (
	"net/http"
	"slices"
	"testing"
)

// TestSim_RevocationLiveness exercises the REVOCATION_LIVENESS invariant from
// ADR 0009: a revoked host's poll loop is stopped promptly and the revocation
// propagates to peers.
//
//   - Block -> the host's next signed poll gets a structured 403 reason=revoked
//     (ADR 0004 §7.1), so the agent stops instead of draining config.
//   - The blocked fingerprint appears in every peer's blocklist on the next poll.
//   - Delete -> the row is gone but DeleteHostAndBlockCert keeps the cert
//     blocklisted, so the poll gets a structured 410 reason=gone.
func TestSim_RevocationLiveness(t *testing.T) {
	h := New(t)
	netID := h.CreateNetwork("revoke-net", "10.50.0.0/16")
	victim := h.Enroll(netID, "victim", "10.50.0.10")
	peer := h.Enroll(netID, "peer", "10.50.0.11")
	victim.DrainToConverged(h, 5)
	peer.DrainToConverged(h, 5)

	if r := victim.Poll(h); r.Status != http.StatusOK {
		t.Fatalf("victim baseline poll: status %d, want 200", r.Status)
	}

	if code := h.API(http.MethodPost, "/api/v1/hosts/"+victim.HostID+"/block", nil, nil); code != http.StatusOK {
		t.Fatalf("block victim: HTTP %d", code)
	}

	// Blocked host: structured 403 revoked so the agent stops the loop.
	if r := victim.Poll(h); r.Status != http.StatusForbidden || r.Reason != "revoked" {
		t.Errorf("REVOCATION_LIVENESS: blocked victim poll = status %d reason %q; want 403 revoked\n%s",
			r.Status, r.Reason, h.Journal.Report(victim.HostID))
	}

	// Propagation: the victim's fingerprint lands in the peer's blocklist.
	if r := peer.Poll(h); !slices.Contains(r.Blocklist, victim.Fingerprint) {
		t.Errorf("REVOCATION_LIVENESS: victim fingerprint %q not in peer blocklist after block; got %v",
			victim.Fingerprint, r.Blocklist)
	}

	// Delete the row; the cert stays blocklisted (DeleteHostAndBlockCert).
	if code := h.API(http.MethodDelete, "/api/v1/hosts/"+victim.HostID, nil, nil); code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("delete victim: HTTP %d", code)
	}

	// Gone host: structured 410 gone.
	if r := victim.Poll(h); r.Status != http.StatusGone || r.Reason != "gone" {
		t.Errorf("REVOCATION_LIVENESS: deleted victim poll = status %d reason %q; want 410 gone\n%s",
			r.Status, r.Reason, h.Journal.Report(victim.HostID))
	}
}
