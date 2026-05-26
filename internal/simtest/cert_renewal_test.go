package simtest

import (
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/pki"
)

// TestSim_CertAutoRenewal is the first time-dependent invariant, unlocked by
// the clock seam (api.Server.WithClock + pki.ShouldRenewAt). A host cert lives
// DefaultAgentCertDuration (30d) and is renewed when <20% remains. We freeze
// the harness clock, confirm a fresh cert is NOT renewed, then advance into the
// renewal window and confirm the next poll auto-renews.
//
// Advancing the harness clock moves the server's now and the agent's poll
// timestamp together, so the PoP timestamp-skew check still passes — that
// lockstep is exactly what the seam buys.
func TestSim_CertAutoRenewal(t *testing.T) {
	h := New(t)
	netID := h.CreateNetwork("renew-net", "10.80.0.0/16")
	a := h.Enroll(netID, "renew-host", "10.80.0.10")
	a.DrainToConverged(h, 5)

	// Freeze the clock at the cert's birth; a fresh 30d cert must not renew.
	h.SetClock(time.Now())
	if r := a.Poll(h); r.CertificatePEM != nil {
		t.Fatalf("cert renewed while fresh (full TTL remaining) — unexpected")
	}

	// Jump to within the <20% renewal window (26/30 days elapsed -> ~13% left).
	h.Advance(26 * 24 * time.Hour)
	if r := a.Poll(h); r.CertificatePEM == nil {
		t.Errorf("CERT_RENEWAL violated: no auto-renewal after advancing into the renewal window "+
			"(threshold %.0f%%); poll returned status %d with no certificate", 100*0.20, r.Status)
	}

	// Sanity on the boundary helper itself.
	nb := time.Unix(0, 0)
	if pki.ShouldRenewAt(nb, nb.Add(30*24*time.Hour), nb.Add(20*24*time.Hour)) {
		t.Error("ShouldRenewAt renewed at 33% remaining; threshold is 20%")
	}
	if !pki.ShouldRenewAt(nb, nb.Add(30*24*time.Hour), nb.Add(26*24*time.Hour)) {
		t.Error("ShouldRenewAt did not renew at 13% remaining; threshold is 20%")
	}
}
