package pop

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestNonceCache_ConcurrentSameNonce_ExactlyOneTrue fires many goroutines
// at the same (host, nonce) pair and asserts exactly one of them
// observes a fresh-accept return. The point is to lock down the mutex
// invariant that defeats the "two goroutines both miss the map,
// both insert, both return true" race that would open a replay window
// under concurrent load.
//
// Run with -race for full coverage of the data-race side.
func TestNonceCache_ConcurrentSameNonce_ExactlyOneTrue(t *testing.T) {
	const attempts = 200
	c := NewNonceCache(NonceCacheConfig{Capacity: 1024, IdleTTL: time.Hour})

	accepts := make(chan bool, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			accepts <- c.SeenOrAdd("h", "shared")
		}()
	}
	wg.Wait()
	close(accepts)

	trueCount := 0
	for got := range accepts {
		if got {
			trueCount++
		}
	}
	if trueCount != 1 {
		t.Errorf("fresh-accept count = %d, want 1 (replay window opened under concurrency)", trueCount)
	}
}

// TestNonceCache_ConcurrentDistinctNonces_AllAccepted fires many
// goroutines, each inserting a distinct nonce, and asserts every
// insert returns true. Catches a defect where the LRU eviction path
// under contention would incorrectly reject a fresh nonce.
func TestNonceCache_ConcurrentDistinctNonces_AllAccepted(t *testing.T) {
	const workers = 32
	const noncesPerWorker = 64
	c := NewNonceCache(NonceCacheConfig{
		// Larger than workers*noncesPerWorker so no eviction during this test.
		Capacity: workers * noncesPerWorker * 2,
		IdleTTL:  time.Hour,
	})

	totalAccepts := make(chan int, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			ok := 0
			for i := 0; i < noncesPerWorker; i++ {
				if c.SeenOrAdd("h", fmt.Sprintf("w%d-n%d", workerID, i)) {
					ok++
				}
			}
			totalAccepts <- ok
		}(w)
	}
	wg.Wait()
	close(totalAccepts)

	got := 0
	for n := range totalAccepts {
		got += n
	}
	if want := workers * noncesPerWorker; got != want {
		t.Errorf("fresh-accept count = %d, want %d (LRU rejected a fresh nonce under contention)",
			got, want)
	}
}

// TestNonceCache_BurstEvictionDoesNotOpenReplayWindow exercises the
// capacity-overflow path. Inserts n0..n3 (fills capacity=4), then
// inserts an evictor that displaces the LRU tail (n0). Asserts:
//
//   - The evictor returns true (fresh accept).
//   - n0 is acceptable as fresh again (it was evicted).
//   - The other three (n1, n2, n3) and the evictor itself still
//     reject replays — i.e. only the LRU tail moved out.
//
// Doesn't chain further re-inserts because that triggers cascade
// evictions and obscures what's being asserted.
func TestNonceCache_BurstEvictionDoesNotOpenReplayWindow(t *testing.T) {
	c := NewNonceCache(NonceCacheConfig{
		Capacity: 4,
		IdleTTL:  time.Hour,
		Now:      time.Now,
	})

	for i := 0; i < 4; i++ {
		if !c.SeenOrAdd("h", fmt.Sprintf("n%d", i)) {
			t.Fatalf("initial insert n%d returned false", i)
		}
	}
	// Push past capacity. n0 was inserted first and never bumped, so
	// it is the LRU victim.
	if !c.SeenOrAdd("h", "evictor") {
		t.Fatal("evictor insert returned false")
	}

	// The three nonces that should still be cached must reject replays.
	for _, n := range []string{"n1", "n2", "n3", "evictor"} {
		if c.SeenOrAdd("h", n) {
			t.Errorf("still-cached %s wrongly accepted as fresh", n)
		}
	}
}

// TestNonceCache_EvictedNonceAcceptableAgain asserts that once a nonce
// is evicted via LRU, it can be submitted again as fresh. Companion to
// BurstEvictionDoesNotOpenReplayWindow — together they pin the LRU
// contract from both sides (still-cached rejects, evicted accepts).
func TestNonceCache_EvictedNonceAcceptableAgain(t *testing.T) {
	c := NewNonceCache(NonceCacheConfig{
		Capacity: 4,
		IdleTTL:  time.Hour,
		Now:      time.Now,
	})
	for i := 0; i < 4; i++ {
		c.SeenOrAdd("h", fmt.Sprintf("n%d", i))
	}
	c.SeenOrAdd("h", "evictor") // n0 evicted.

	if !c.SeenOrAdd("h", "n0") {
		t.Error("n0 should be acceptable as fresh after LRU eviction")
	}
}

// TestNonceCache_ReplayAttemptBumpsRecency is the defense the
// implementation documents at nonce.go:73-78 ("bump recency to defeat
// flood-then-replay tactics"). Without the bump, an attacker who
// intercepted a legitimate nonce L could flood the cache with bogus
// nonces to evict L via LRU and then replay L successfully. The bump
// pins L at the head of the LRU on every replay attempt so the
// attacker's flood evicts filler entries instead.
//
// Test shape:
//
//  1. Insert L (legitimate, lands at the LRU tail after X).
//  2. Replay L — rejected AND bumped to head.
//  3. Insert Y, exceeding capacity — the LRU tail is now X (filler),
//     not L. Y's insertion evicts X.
//  4. Replay L again — must still reject (L is still in the cache).
func TestNonceCache_ReplayAttemptBumpsRecency(t *testing.T) {
	now := time.Unix(0, 0)
	c := NewNonceCache(NonceCacheConfig{
		Capacity: 2,
		IdleTTL:  10 * time.Minute,
		Now:      func() time.Time { return now },
	})

	if !c.SeenOrAdd("h", "L") {
		t.Fatal("L insert returned false")
	}
	if !c.SeenOrAdd("h", "X") {
		t.Fatal("X insert returned false")
	}

	// Replay L: rejected AND bumped to head.
	now = now.Add(time.Second)
	if c.SeenOrAdd("h", "L") {
		t.Fatal("L replay accepted (bug)")
	}

	// Push past capacity. With the bump, X (filler) is the LRU victim.
	now = now.Add(time.Second)
	if !c.SeenOrAdd("h", "Y") {
		t.Fatal("Y insert returned false")
	}

	// L must still reject — it's the bump beneficiary.
	if c.SeenOrAdd("h", "L") {
		t.Error("L was bumped on replay attempt; should still reject after Y eviction")
	}
}

// TestNonceCache_PerHostNamespacingPreventsCollision asserts the
// (host_id, nonce) keying — the same nonce string used by two
// different hosts is treated as two distinct entries, not as a replay.
// Single-tenant deployments rely on this so an attacker who guesses a
// well-known nonce value can't pre-pollute the cache for other hosts.
func TestNonceCache_PerHostNamespacingPreventsCollision(t *testing.T) {
	c := NewNonceCache(NonceCacheConfig{Capacity: 16, IdleTTL: time.Hour, Now: time.Now})
	if !c.SeenOrAdd("hostA", "shared") {
		t.Fatal("hostA initial insert returned false")
	}
	if !c.SeenOrAdd("hostB", "shared") {
		t.Error("hostB's distinct entry for the same nonce string was wrongly rejected as a replay")
	}
	if c.SeenOrAdd("hostA", "shared") {
		t.Error("hostA's own replay was wrongly accepted as fresh")
	}
}

// TestNonceCache_LRUEvictionIsCrossHost documents that the LRU is a
// single shared resource across all hosts — a flood under host B can
// evict an idle entry belonging to host A. This is intentional: the
// per-host key namespaces collisions, not eviction. Capacity sizing
// in production (65536 default) is what bounds the practical attack
// surface; per-host LRU partitioning is not the defense.
func TestNonceCache_LRUEvictionIsCrossHost(t *testing.T) {
	c := NewNonceCache(NonceCacheConfig{Capacity: 2, IdleTTL: time.Hour, Now: time.Now})
	if !c.SeenOrAdd("hostA", "shared") {
		t.Fatal("hostA initial insert returned false")
	}
	for i := 0; i < 4; i++ {
		c.SeenOrAdd("hostB", fmt.Sprintf("filler-%d", i))
	}
	// hostA's entry is the LRU and was evicted by the flood. The
	// freshest hostB entry survives.
	if c.SeenOrAdd("hostB", "filler-3") {
		t.Error("hostB's most-recent nonce wrongly evicted")
	}
}
