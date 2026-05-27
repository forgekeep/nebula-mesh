package simtest

import (
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"
)

// TestSim_ScaleBlocklistPropagation is the scale leg of ADR 0009. It enrolls a
// fleet, blocks a subset, and checks two correctness properties plus surfaces a
// documented scaling smell.
//
// Correctness:
//   - all blocked fingerprints propagate to an unblocked host's next poll;
//   - blocking does NOT trigger a config re-render (config_yaml stays nil) —
//     handleBlockHost ships the blocklist without bumping the network config
//     version, so a block is O(blocklist), not an O(N) re-render storm.
//
// Smell (logged, not asserted, since it is the current intended behavior):
//   - once anything is blocked, has_updates is true and the full blocklist
//     ships on every poll by every host regardless of churn (internal/api/
//     updates.go). At fleet scale that is a standing O(blocklist x hosts /
//     poll_interval) cost.
func TestSim_ScaleBlocklistPropagation(t *testing.T) {
	const (
		fleet   = 60
		blocked = 10
	)
	h := New(t) // payload/propagation test, not concurrency — :memory: is fine

	netID := h.CreateNetwork("scale-net", "10.60.0.0/16")
	agents := make([]*Agent, fleet)
	t0 := time.Now()
	for i := range agents {
		agents[i] = h.Enroll(netID, fmt.Sprintf("h-%03d", i), fmt.Sprintf("10.60.%d.%d", i/250, i%250+1))
		agents[i].DrainToConverged(h, 5)
	}
	t.Logf("enrolled+converged %d hosts in %s", fleet, time.Since(t0).Round(time.Millisecond))

	// Baseline: a converged host's poll is quiet (nothing blocked yet).
	if r := agents[0].Poll(h); r.HasUpdates || len(r.Blocklist) != 0 || r.ConfigYAML != nil {
		t.Errorf("steady state not quiet before any block: has_updates=%v blocklist=%d config=%v",
			r.HasUpdates, len(r.Blocklist), r.ConfigYAML != nil)
	}

	// Block the tail of the fleet.
	var blockedFPs []string
	for i := 0; i < blocked; i++ {
		v := agents[fleet-1-i]
		if code := h.API(http.MethodPost, "/api/v1/hosts/"+v.HostID+"/block", nil, nil); code != http.StatusOK {
			t.Fatalf("block %s: HTTP %d", v.Name, code)
		}
		blockedFPs = append(blockedFPs, v.Fingerprint)
	}

	// An unblocked host's next poll must carry every blocked fingerprint, and
	// must NOT re-render config (a block is not a network config change).
	r := agents[0].Poll(h)
	for _, fp := range blockedFPs {
		if !slices.Contains(r.Blocklist, fp) {
			t.Errorf("blocked fingerprint %q did not propagate to unblocked host's blocklist", fp)
		}
	}
	if r.ConfigYAML != nil {
		t.Errorf("blocking triggered a config re-render (config_yaml non-nil) — should be O(blocklist), not an O(N) re-render storm")
	}

	t.Logf("SCALE SMELL: after blocking %d/%d, an unblocked host's steady-state poll reports has_updates=%v and ships the full %d-entry blocklist; this repeats on every poll by every host regardless of churn",
		blocked, fleet, r.HasUpdates, len(r.Blocklist))
}
