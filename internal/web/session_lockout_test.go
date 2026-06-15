package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// attemptLogin drives SessionManager.Login once and returns whether it
// succeeded. The ResponseRecorder absorbs any Set-Cookie writes.
func attemptLogin(t *testing.T, sm *SessionManager, username, password string) bool {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ui/login", nil)
	_, ok, err := sm.Login(rec, req, username, password)
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	return ok
}

// TestLogin_LockoutAfterRepeatedFailures verifies the per-account lockout (#263):
// after maxFailedLoginAttempts wrong passwords the account is locked, and while
// locked even the correct password is rejected without creating a session.
func TestLogin_LockoutAfterRepeatedFailures(t *testing.T) {
	_, s := newOperatorsWeb(t)
	op, _ := passwordOperator(t, s, "lockme", "tok-lockme")
	sm := NewSessionManager(s)

	for i := 0; i < maxFailedLoginAttempts; i++ {
		if attemptLogin(t, sm, "lockme", "wrong-password") {
			t.Fatalf("attempt %d: wrong password should not succeed", i+1)
		}
	}

	got, err := s.GetOperator(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.LockedUntil == nil || !got.LockedUntil.After(time.Now()) {
		t.Fatalf("account should be locked after %d failures; LockedUntil=%v", maxFailedLoginAttempts, got.LockedUntil)
	}

	// While locked, the correct password is also rejected and no session row
	// is created (the lock takes precedence over a valid credential).
	if attemptLogin(t, sm, "lockme", oldPassword) {
		t.Fatal("correct password should be rejected while account is locked")
	}
}

// TestLogin_SucceedsAfterLockExpires verifies an expired lock is cleared so the
// correct password works again (and the counter is reset).
func TestLogin_SucceedsAfterLockExpires(t *testing.T) {
	_, s := newOperatorsWeb(t)
	op, _ := passwordOperator(t, s, "expireme", "tok-expireme")
	sm := NewSessionManager(s)
	ctx := context.Background()

	// Simulate an already-expired lock by recording a failure with a lock time
	// in the past (threshold 1 → locks immediately, but at a past instant).
	if _, err := s.RecordFailedLoginAttempt(ctx, op.ID, 1, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	if !attemptLogin(t, sm, "expireme", oldPassword) {
		t.Fatal("correct password should succeed once the lock has expired")
	}

	got, err := s.GetOperator(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
		t.Errorf("after successful login: attempts=%d locked=%v, want 0/nil", got.FailedLoginAttempts, got.LockedUntil)
	}
}

// TestLogin_SuccessResetsCounter verifies a successful login clears a partial
// failure streak so it never accumulates toward a lock across good logins.
func TestLogin_SuccessResetsCounter(t *testing.T) {
	_, s := newOperatorsWeb(t)
	op, _ := passwordOperator(t, s, "resetme", "tok-resetme")
	sm := NewSessionManager(s)
	ctx := context.Background()

	// A couple of failures below the threshold.
	for i := 0; i < 3; i++ {
		if attemptLogin(t, sm, "resetme", "wrong-password") {
			t.Fatalf("attempt %d should fail", i+1)
		}
	}
	if !attemptLogin(t, sm, "resetme", oldPassword) {
		t.Fatal("correct password should succeed below the lock threshold")
	}
	got, err := s.GetOperator(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d after success, want 0", got.FailedLoginAttempts)
	}
}

// TestLogin_OIDCAccountNotLocked verifies password-login failures against an
// OIDC operator do not accumulate a lock (they have no local password; OIDC
// login goes through HandleCallback, not Login).
func TestLogin_OIDCAccountNotLocked(t *testing.T) {
	_, s := newOperatorsWeb(t)
	ctx := context.Background()
	oidc := &models.Operator{
		ID:           "op-oidcuser",
		Username:     "oidcuser",
		PasswordHash: "oidc",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthOIDC,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, oidc); err != nil {
		t.Fatal(err)
	}
	sm := NewSessionManager(s)

	for i := 0; i < maxFailedLoginAttempts+2; i++ {
		if attemptLogin(t, sm, "oidcuser", "any-password") {
			t.Fatalf("attempt %d: OIDC account should never authenticate via password", i+1)
		}
	}
	got, err := s.GetOperator(ctx, oidc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
		t.Errorf("OIDC account should not be locked: attempts=%d locked=%v", got.FailedLoginAttempts, got.LockedUntil)
	}
}
