package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
)

// TestConsumeToken_AtomicUnderConcurrency fires N goroutines at the
// same enrollment token and asserts exactly one observes success while
// the other N-1 receive ErrTokenUsed. The property guarded here is the
// at-most-once semantics of enrollment-token consumption — if two
// agents racing the same leaked token both saw success, both could
// enroll fresh keypairs against the same host row, breaking the
// single-host-per-token invariant the agent-auth design assumes.
//
// Run with -race for full coverage of the data-race side.
//
// Note: this test deliberately uses a file-backed store rather than the
// shared newTestStore helper. The helper opens ":memory:" which forces
// SetMaxOpenConns(1) (see sqlite.go: dbPath == ":memory:" branch); all
// goroutines would then serialize through a single connection and any
// "broken" implementation that splits SELECT/UPDATE across un-tx'd
// calls would still pass. A file-backed DSN lets the connection pool
// grow, so the race the production code's transaction + busy_timeout
// defends against is actually exercised.
//
// Existing happy-path / used / expired / not-found cases are covered
// by TestConsumeToken_{Success,AlreadyUsed,Expired,NotFound} in
// sqlite_test.go. This file covers only the concurrency property
// those tests cannot exercise.
func TestConsumeToken_AtomicUnderConcurrency(t *testing.T) {
	const workers = 10

	dbPath := filepath.Join(t.TempDir(), "cas.db")
	s, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ctx := context.Background()
	h := newHostFixture(t, s, "h1")

	const raw = "single-shared-token"
	if err := s.CreateTokenForHost(ctx, h.ID, raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create token: %v", err)
	}

	type outcome struct {
		token *models.EnrollmentToken
		err   error
	}
	results := make(chan outcome, workers)
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer done.Done()
			start.Wait() // release-the-hounds to maximize contention.
			tok, err := s.ConsumeToken(ctx, raw)
			results <- outcome{token: tok, err: err}
		}()
	}
	start.Done()
	done.Wait()
	close(results)

	var (
		successes int
		losses    int // ErrTokenUsed (CAS lost) or SQLITE_BUSY (lock contention timed out)
		other     []error
		winners   []string
	)
	for r := range results {
		switch {
		case r.err == nil:
			successes++
			if r.token == nil {
				t.Error("nil err but nil token — implementation bug")
				continue
			}
			winners = append(winners, r.token.ID)
		case errors.Is(r.err, ErrTokenUsed):
			losses++
		case strings.Contains(r.err.Error(), "database is locked"):
			// SQLITE_BUSY: under heavy CI runner contention the
			// busy_timeout occasionally trips before this worker
			// reaches its CAS attempt. The at-most-once invariant
			// (single winner, no double-consume) is unaffected —
			// pinned by the successes==1 assertion below. Treating
			// SQLITE_BUSY as a valid loss outcome keeps the test
			// honest about what it actually guards (atomicity, not
			// busy_timeout calibration).
			losses++
		default:
			other = append(other, r.err)
		}
	}

	if successes != 1 {
		t.Errorf("successes = %d, want 1 (token consumed more than once — CAS broken)", successes)
	}
	if losses != workers-1 {
		t.Errorf("loss count = %d, want %d (ErrTokenUsed + SQLITE_BUSY)", losses, workers-1)
	}
	if len(other) != 0 {
		t.Errorf("unexpected error returns: %v", other)
	}
	if len(winners) > 1 {
		t.Errorf("multiple winner token IDs: %v", winners)
	}
}
