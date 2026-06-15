package store

import (
	"context"
	"testing"
	"time"
)

// TestOperatorLockout_DefaultsAndMethods covers the per-account lockout store
// surface (#263): fresh operators start unlocked; RecordFailedLoginAttempt
// increments and locks at the threshold; ResetFailedLoginAttempts clears both.
func TestOperatorLockout_DefaultsAndMethods(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "mallory")

	// Fresh operator: zero attempts, no lock.
	got, err := s.GetOperator(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailedLoginAttempts != 0 {
		t.Errorf("fresh FailedLoginAttempts = %d, want 0", got.FailedLoginAttempts)
	}
	if got.LockedUntil != nil {
		t.Errorf("fresh LockedUntil = %v, want nil", got.LockedUntil)
	}

	const maxAttempts = 5
	lockUntil := time.Now().Add(15 * time.Minute)

	// The first maxAttempts-1 failures must not lock.
	for i := 1; i < maxAttempts; i++ {
		locked, err := s.RecordFailedLoginAttempt(ctx, op.ID, maxAttempts, lockUntil)
		if err != nil {
			t.Fatalf("record attempt %d: %v", i, err)
		}
		if locked {
			t.Fatalf("locked after %d attempts, want lock only at %d", i, maxAttempts)
		}
	}
	got, _ = s.GetOperator(ctx, op.ID)
	if got.FailedLoginAttempts != maxAttempts-1 {
		t.Errorf("FailedLoginAttempts = %d, want %d", got.FailedLoginAttempts, maxAttempts-1)
	}
	if got.LockedUntil != nil {
		t.Errorf("LockedUntil set before threshold: %v", got.LockedUntil)
	}

	// The maxAttempts-th failure locks the account.
	locked, err := s.RecordFailedLoginAttempt(ctx, op.ID, maxAttempts, lockUntil)
	if err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Fatal("expected account locked at threshold")
	}
	got, _ = s.GetOperator(ctx, op.ID)
	if got.LockedUntil == nil {
		t.Fatal("LockedUntil should be set after threshold")
	}

	// Reset clears both counter and lock.
	if err := s.ResetFailedLoginAttempts(ctx, op.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetOperator(ctx, op.ID)
	if got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
		t.Errorf("after reset: attempts=%d locked=%v, want 0/nil", got.FailedLoginAttempts, got.LockedUntil)
	}
}
