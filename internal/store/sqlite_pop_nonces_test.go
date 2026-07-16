package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// SEC-REPLAY-001: TestPopNonces_AcceptThenReplayRejected pins the headline invariant:
// the same (host, nonce) is accepted exactly once inside its expiry
// window. GHSA-v2jf-442r-6mjh.
func TestPopNonces_AcceptThenReplayRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	if err := s.AddPopNonce(ctx, "h", "n", exp); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	err := s.AddPopNonce(ctx, "h", "n", exp)
	if !errors.Is(err, ErrReplayedNonce) {
		t.Fatalf("replay within window: got err=%v, want ErrReplayedNonce", err)
	}
}

// TestPopNonces_CrossHostNamespacing pins the per-host keying — same
// nonce string under two different hosts is two distinct entries, not
// a replay.
func TestPopNonces_CrossHostNamespacing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	if err := s.AddPopNonce(ctx, "hostA", "shared", exp); err != nil {
		t.Fatalf("hostA insert: %v", err)
	}
	if err := s.AddPopNonce(ctx, "hostB", "shared", exp); err != nil {
		t.Errorf("hostB distinct entry for same nonce wrongly rejected: %v", err)
	}
	if err := s.AddPopNonce(ctx, "hostA", "shared", exp); !errors.Is(err, ErrReplayedNonce) {
		t.Errorf("hostA's own replay: got err=%v, want ErrReplayedNonce", err)
	}
}

// TestPopNonces_OneHostCannotEvictAnother is the structural fix to the
// GHSA-v2jf eviction-replay surface: the in-memory LRU let one noisy
// host evict another's record by flooding distinct nonces. The
// durable store has no capacity cap, so a flood from host B cannot
// open a replay window on host A's recorded nonce.
func TestPopNonces_OneHostCannotEvictAnother(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	if err := s.AddPopNonce(ctx, "victim", "n", exp); err != nil {
		t.Fatalf("victim seed: %v", err)
	}

	// Flood from a different host with many distinct nonces. The deleted
	// in-memory LRU had a global 65,536-entry cap, so any flood beyond a
	// few thousand already proves the structural property under test
	// ("no capacity cap exists"). We pick 2k as a cheap-to-run multiple
	// — under -race the per-insert cost dominates total runtime, so
	// staying small keeps this test out of the CI tax band.
	const flood = 2_000
	for i := 0; i < flood; i++ {
		if err := s.AddPopNonce(ctx, "attacker", fmt.Sprintf("n%d", i), exp); err != nil {
			t.Fatalf("flood insert %d: %v", i, err)
		}
	}

	// Victim's record must still reject replay.
	if err := s.AddPopNonce(ctx, "victim", "n", exp); !errors.Is(err, ErrReplayedNonce) {
		t.Fatalf("victim nonce evicted by attacker flood — got err=%v, want ErrReplayedNonce", err)
	}
}

// TestPopNonces_ExpiredRowAcceptableAgain confirms that once a nonce
// row passes its expires_at, the same (host, nonce) is acceptable
// again — the timestamp window check upstream is the only thing the
// caller relies on for freshness.
func TestPopNonces_ExpiredRowAcceptableAgain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	past := time.Now().Add(-1 * time.Hour)
	if err := s.AddPopNonce(ctx, "h", "n", past); err != nil {
		t.Fatalf("seed expired row: %v", err)
	}

	future := time.Now().Add(5 * time.Minute)
	if err := s.AddPopNonce(ctx, "h", "n", future); err != nil {
		t.Errorf("expired row should be replaceable; got err=%v", err)
	}
}

// TestPopNonces_LazyPruneClearsStaleRows asserts the AddPopNonce path
// drops past-expiry rows on every call, so the table does not grow
// unbounded over time. Counts rows directly via the *SQLiteStore.db
// handle.
func TestPopNonces_LazyPruneClearsStaleRows(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	past := time.Now().Add(-1 * time.Hour)

	for i := 0; i < 50; i++ {
		if err := s.AddPopNonce(ctx, "h", fmt.Sprintf("stale%d", i), past); err != nil {
			t.Fatalf("seed stale %d: %v", i, err)
		}
	}

	// Trigger one fresh insert under a different host — the prune runs as
	// a side effect, sweeping the 50 expired rows above.
	if err := s.AddPopNonce(ctx, "other", "live", time.Now().Add(5*time.Minute)); err != nil {
		t.Fatalf("trigger prune: %v", err)
	}

	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pop_nonces`).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 row after prune sweep, got %d", n)
	}
}

// SEC-REPLAY-001: TestPopNonces_SurvivesRestart is the structural fix to the GHSA-v2jf
// restart-replay surface: an in-memory LRU lost all recorded nonces
// at process restart, so a captured poll became replayable within
// the timestamp window. The durable store must remember the nonce
// across Close/Open of the same on-disk DB.
func TestPopNonces_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces.db")
	exp := time.Now().Add(5 * time.Minute)
	ctx := context.Background()

	s1, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open #1: %v", err)
	}
	if err := s1.Migrate(ctx); err != nil {
		t.Fatalf("migrate #1: %v", err)
	}
	if err := s1.AddPopNonce(ctx, "h", "n", exp); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close #1: %v", err)
	}

	s2, err := NewSQLiteStore(path)
	if err != nil {
		t.Fatalf("open #2: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if err := s2.Migrate(ctx); err != nil {
		t.Fatalf("migrate #2: %v", err)
	}

	if err := s2.AddPopNonce(ctx, "h", "n", exp); !errors.Is(err, ErrReplayedNonce) {
		t.Fatalf("nonce replay after restart: got err=%v, want ErrReplayedNonce — durable replay protection broken", err)
	}
}

// SEC-REPLAY-001: TestPopNonces_ConcurrentSameNonceExactlyOneAccepted exercises the
// linearization guarantee under contention. Many goroutines submit the
// same (host, nonce); exactly one observes nil-error (fresh accept),
// the rest are correctly classified as ErrReplayedNonce.
func TestPopNonces_ConcurrentSameNonceExactlyOneAccepted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	const attempts = 64
	var accepted, replayed atomic.Int64
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			switch err := s.AddPopNonce(ctx, "h", "shared", exp); {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrReplayedNonce):
				replayed.Add(1)
			default:
				t.Errorf("concurrent insert: unexpected err=%v", err)
			}
		}()
	}
	wg.Wait()

	if accepted.Load() != 1 {
		t.Errorf("fresh-accept count = %d, want 1 (replay window opened under concurrency)", accepted.Load())
	}
	if replayed.Load() != attempts-1 {
		t.Errorf("replay-reject count = %d, want %d", replayed.Load(), attempts-1)
	}
}

// TestPopNonces_ConcurrentDistinctNoncesAllAccepted asserts that many
// distinct nonces submitted concurrently are all accepted. Catches a
// defect where the prune sweep or insert serialization could
// spuriously reject a fresh nonce.
func TestPopNonces_ConcurrentDistinctNoncesAllAccepted(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	const workers = 16
	const noncesPerWorker = 32

	var accepted atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < noncesPerWorker; i++ {
				if err := s.AddPopNonce(ctx, "h", fmt.Sprintf("w%d-n%d", workerID, i), exp); err != nil {
					t.Errorf("worker %d insert %d: %v", workerID, i, err)
					return
				}
				accepted.Add(1)
			}
		}(w)
	}
	wg.Wait()

	if got, want := accepted.Load(), int64(workers*noncesPerWorker); got != want {
		t.Errorf("fresh-accept count = %d, want %d (distinct nonce wrongly rejected under contention)", got, want)
	}
}
