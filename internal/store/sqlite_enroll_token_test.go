package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestGetEnrollmentToken_PeekDoesNotConsume verifies the read-only peek resolves
// a token and validates it WITHOUT marking it used, and surfaces the same
// sentinels as ConsumeToken.
func TestGetEnrollmentToken_PeekDoesNotConsume(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "peek-host")

	const raw = "peek-token"
	if err := s.CreateTokenForHost(ctx, h.ID, raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Two peeks in a row both succeed — peek must not consume.
	for i := 0; i < 2; i++ {
		tok, err := s.GetEnrollmentToken(ctx, raw)
		if err != nil {
			t.Fatalf("peek %d: %v", i, err)
		}
		if tok.HostID != h.ID {
			t.Errorf("peek host_id = %q, want %q", tok.HostID, h.ID)
		}
		if tok.Used {
			t.Errorf("peek %d: token reported used", i)
		}
	}

	// Unknown token → ErrNotFound.
	if _, err := s.GetEnrollmentToken(ctx, "no-such-token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token err = %v, want ErrNotFound", err)
	}

	// After an atomic consume+enroll, the peek reports the token used.
	if err := s.ConsumeTokenAndEnrollHost(ctx, h.ID, raw, []byte("cert"), "fp-peek", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("consume+enroll: %v", err)
	}
	if _, err := s.GetEnrollmentToken(ctx, raw); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("post-consume peek err = %v, want ErrTokenUsed", err)
	}
}

// TestGetEnrollmentToken_Expired confirms the peek surfaces ErrTokenExpired (the
// 410 path in handleEnroll), matching ConsumeToken's sentinel set.
func TestGetEnrollmentToken_Expired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "exp-host")

	const raw = "exp-token"
	if err := s.CreateTokenForHost(ctx, h.ID, raw, time.Now().Add(-time.Minute)); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if _, err := s.GetEnrollmentToken(ctx, raw); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired token err = %v, want ErrTokenExpired", err)
	}
}

// TestConsumeTokenAndEnrollHost_NoBurnOnEnrollFailure proves the atomicity that
// closes the burn window: when the enroll step fails (here: a host that does not
// exist), the token consume rolls back with it and the token stays usable —
// instead of being permanently burned as it was when ConsumeToken committed up
// front in a separate transaction.
func TestConsumeTokenAndEnrollHost_NoBurnOnEnrollFailure(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "burn-host")

	const raw = "burn-token"
	if err := s.CreateTokenForHost(ctx, h.ID, raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create token: %v", err)
	}

	// Enroll against a non-existent host → enrollHostInTx fails → the whole tx
	// rolls back, including the token consume.
	err := s.ConsumeTokenAndEnrollHost(ctx, "no-such-host", raw, []byte("cert"), "fp-burn", time.Now(), time.Now().Add(time.Hour))
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}

	// Token must still be usable — no burn.
	tok, err := s.GetEnrollmentToken(ctx, raw)
	if err != nil {
		t.Fatalf("token should still be usable after failed enroll: %v", err)
	}
	if tok.Used {
		t.Error("token was consumed despite enroll failure (burn not prevented)")
	}

	// And a subsequent valid enrollment still succeeds.
	if err := s.ConsumeTokenAndEnrollHost(ctx, h.ID, raw, []byte("cert"), "fp-burn-2", time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("retry enroll: %v", err)
	}
}

// TestConsumeTokenAndEnrollHost_ConcurrentSameToken_ExactlyOneEnrolls fires N
// goroutines at one token (as two agents racing a leaked token would) and
// asserts exactly one enrolls while the rest get ErrTokenUsed — single-use holds
// even with the consume folded into the enroll transaction. File-backed so the
// connection pool actually grows (see TestConsumeToken_AtomicUnderConcurrency
// for why :memory' would mask this). Run with -race.
func TestConsumeTokenAndEnrollHost_ConcurrentSameToken_ExactlyOneEnrolls(t *testing.T) {
	const workers = 10

	dbPath := filepath.Join(t.TempDir(), "enroll.db")
	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	h := newHostFixture(t, s, "race-host")
	const raw = "race-token"
	if err := s.CreateTokenForHost(ctx, h.ID, raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create token: %v", err)
	}

	var wins, losses atomic.Int64
	var mu sync.Mutex
	var other []error
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer done.Done()
			start.Wait() // release-the-hounds to maximize contention.
			err := s.ConsumeTokenAndEnrollHost(ctx, h.ID, raw, []byte("cert"), fmt.Sprintf("fp-%d", i), time.Now(), time.Now().Add(time.Hour))
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, ErrTokenUsed):
				losses.Add(1)
			case strings.Contains(err.Error(), "database is locked"):
				// SQLITE_BUSY under contention — a valid loss; the single-winner
				// invariant is pinned by wins==1 below.
				losses.Add(1)
			default:
				mu.Lock()
				other = append(other, err)
				mu.Unlock()
			}
		}(i)
	}
	start.Done()
	done.Wait()

	if wins.Load() != 1 {
		t.Errorf("successes = %d, want 1 (token enrolled more than once — CAS broken)", wins.Load())
	}
	if losses.Load() != workers-1 {
		t.Errorf("losses = %d, want %d (ErrTokenUsed + SQLITE_BUSY)", losses.Load(), workers-1)
	}
	if len(other) != 0 {
		t.Errorf("unexpected errors: %v", other)
	}

	// Token consumed exactly once, and the winner's cert was persisted.
	if _, err := s.GetEnrollmentToken(ctx, raw); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("token peek err = %v, want ErrTokenUsed", err)
	}
	gotHost, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	if !strings.HasPrefix(gotHost.CertFingerprint, "fp-") {
		t.Errorf("host cert_fingerprint = %q, want the winner's fp-N", gotHost.CertFingerprint)
	}
}
