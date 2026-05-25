package cli

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestSeedAdminOperator_ConcurrentBootDoesNotDuplicate exercises the
// first-boot race: N concurrent callers attempt to seed an admin operator
// against an empty store. Before the atomic SeedInitialAdminOperator path,
// every goroutine's ListOperators saw an empty table and every one wrote a
// fresh admin row with a fresh UUID, so the operators table ended up with
// N admins. The contract this test pins:
//
//   - Exactly ONE caller reports `seeded == true`.
//   - The other N-1 callers report `seeded == false` with err == nil.
//   - Exactly ONE row exists in the operators table afterward.
//   - Exactly ONE row exists in the operator_api_keys table afterward
//     (because every caller passed apiKey != "").
//
// Mirrors netbird's TestCreateOwnerUser_ConcurrentRequests (PR #5754) for
// the same bug-class on their owner-seeding path.
func TestSeedAdminOperator_ConcurrentBootDoesNotDuplicate(t *testing.T) {
	const workers = 10

	// Use a file-backed database so the connection pool can hand each
	// goroutine its own *sql.Conn. ":memory:" would force MaxOpenConns(1)
	// (see NewSQLiteStore) which serializes the workers on a single
	// connection and never actually exercises the WAL-mode multi-writer
	// path the conditional INSERT relies on.
	dbPath := filepath.Join(t.TempDir(), "seed.db")
	s, err := store.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var (
		wg          sync.WaitGroup
		seededCount atomic.Int32
		errs        = make(chan error, workers)
		start       = make(chan struct{})
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			seeded, err := SeedAdminOperator(context.Background(), s, "init-password", "init-api-key")
			if err != nil {
				errs <- err
				return
			}
			if seeded {
				seededCount.Add(1)
			}
		}()
	}

	// Release all workers simultaneously to maximize the race window.
	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("worker returned error: %v", err)
	}

	if got := seededCount.Load(); got != 1 {
		t.Errorf("seeded count = %d, want exactly 1", got)
	}

	ops, err := s.ListOperators(context.Background())
	if err != nil {
		t.Fatalf("list operators: %v", err)
	}
	if len(ops) != 1 {
		t.Errorf("operators count = %d, want 1", len(ops))
	} else if ops[0].Username != DefaultAdminUsername {
		t.Errorf("operator username = %q, want %q", ops[0].Username, DefaultAdminUsername)
	}

	keys, err := s.ListOperatorAPIKeys(context.Background(), ops[0].ID)
	if err != nil {
		t.Fatalf("list api keys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("api keys count = %d, want 1", len(keys))
	}
}

// TestSeedAdminOperator_NoSecretIsNoOp guards the existing
// nothing-configured shortcut: when both uiPassword and apiKey are empty,
// the seeder must return (false, nil) without touching the store.
func TestSeedAdminOperator_NoSecretIsNoOp(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	seeded, err := SeedAdminOperator(context.Background(), s, "", "")
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if seeded {
		t.Error("seeded = true with empty secrets, want false")
	}

	ops, err := s.ListOperators(context.Background())
	if err != nil {
		t.Fatalf("list operators: %v", err)
	}
	if len(ops) != 0 {
		t.Errorf("operators count = %d, want 0", len(ops))
	}
}

// TestSeedAdminOperator_IdempotentOnPopulatedStore pins the second-call
// no-op contract: once an admin has been seeded, a subsequent SeedAdmin
// call must report (false, nil) and not mutate the store.
func TestSeedAdminOperator_IdempotentOnPopulatedStore(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	seeded, err := SeedAdminOperator(context.Background(), s, "first-password", "first-key")
	if err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if !seeded {
		t.Fatal("first seed = false, want true")
	}

	seeded, err = SeedAdminOperator(context.Background(), s, "second-password", "second-key")
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if seeded {
		t.Error("second seed = true, want false (already populated)")
	}

	ops, err := s.ListOperators(context.Background())
	if err != nil {
		t.Fatalf("list operators: %v", err)
	}
	if len(ops) != 1 {
		t.Errorf("operators count = %d, want 1 after second call", len(ops))
	}
}
