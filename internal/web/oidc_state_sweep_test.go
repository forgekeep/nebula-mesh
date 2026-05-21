package web

import (
	"strconv"
	"testing"
	"time"
)

// TestOIDC_RememberState_SweepsExpired confirms that the lazy TTL sweeper
// drops entries past their expiry on every rememberState call. Without
// this, an unauthenticated client bursting /ui/oidc/login grows the
// states map without bound (DoS amplifier).
func TestOIDC_RememberState_SweepsExpired(t *testing.T) {
	o := newOIDCForStateTests(t)

	const liveCount = 5
	const expiredCount = 20

	// Plant entries by direct mutation so the sweep isn't triggered
	// between inserts. Fresh entries get a future expiry; expired entries
	// get a past one. Once the map is fully populated, trigger the sweep
	// with a single rememberState call.
	now := time.Now()
	future := now.Add(oidcStateTTL)
	past := now.Add(-time.Minute)
	o.stateMu.Lock()
	for i := 0; i < liveCount; i++ {
		o.states["live-"+strconv.Itoa(i)] = future
	}
	for i := 0; i < expiredCount; i++ {
		o.states["expired-"+strconv.Itoa(i)] = past
	}
	o.stateMu.Unlock()

	if got := o.stateCount(); got != liveCount+expiredCount {
		t.Fatalf("pre-sweep state count = %d, want %d", got, liveCount+expiredCount)
	}

	// Trigger the lazy sweep by remembering one more state.
	o.rememberState("trigger-sweep")

	want := liveCount + 1 // the live ones plus the trigger
	if got := o.stateCount(); got != want {
		t.Errorf("post-sweep state count = %d, want %d", got, want)
	}

	// Spot-check: every entry left in the map must have a future expiry.
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	checkpoint := time.Now()
	for state, exp := range o.states {
		if !exp.After(checkpoint) {
			t.Errorf("post-sweep state %q has stale expiry %v", state, exp)
		}
	}
}

// TestOIDC_RememberState_BurstDoesNotGrowUnbounded simulates the DoS
// amplifier shape: a burst of /ui/oidc/login hits after which the entries
// expire. The next rememberState must not leave the old entries behind.
func TestOIDC_RememberState_BurstDoesNotGrowUnbounded(t *testing.T) {
	o := newOIDCForStateTests(t)

	// Simulate an attacker burst that pre-dates the TTL window.
	const burst = 1000
	past := time.Now().Add(-2 * oidcStateTTL)
	for i := 0; i < burst; i++ {
		s := "burst-" + strconv.Itoa(i)
		o.stateMu.Lock()
		o.states[s] = past
		o.stateMu.Unlock()
	}
	if got := o.stateCount(); got != burst {
		t.Fatalf("pre-sweep state count = %d, want %d", got, burst)
	}

	o.rememberState("legitimate-login")

	// The burst entries should all be gone; only the legitimate login
	// remains.
	if got := o.stateCount(); got != 1 {
		t.Errorf("post-sweep state count = %d, want 1 (DoS map grew unbounded)", got)
	}
}
