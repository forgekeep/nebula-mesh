package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestDummyPasswordHashCost pins the timing-equalizer hash to the same cost as
// production password hashes, so the dummy compare really does take ~the same
// time as a real one (#180).
func TestDummyPasswordHashCost(t *testing.T) {
	cost, err := bcrypt.Cost(dummyPasswordHash)
	if err != nil {
		t.Fatalf("bcrypt.Cost(dummyPasswordHash): %v", err)
	}
	if cost != bcrypt.DefaultCost {
		t.Fatalf("dummy hash cost = %d, want bcrypt.DefaultCost (%d)", cost, bcrypt.DefaultCost)
	}
}

// TestLogin_ConstantTimeAcrossAccountStates verifies the unknown-username and
// inactive-account paths spend comparable time to the real password-verify
// path. Uses a relative bound (>= half the genuine bcrypt path) so it is
// independent of machine speed: without the dummy compare these paths return
// in microseconds and the test fails (#180).
func TestLogin_ConstantTimeAcrossAccountStates(t *testing.T) {
	ctx := context.Background()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("correct-horse"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	mkOp := func(id, name string, status models.OperatorStatus) {
		if err := s.CreateOperator(ctx, &models.Operator{
			ID: id, Username: name, PasswordHash: string(hash), Role: "admin",
			Status: status, AuthProvider: models.OperatorAuthLocal,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	mkOp("op-active", "alice", models.OperatorStatusActive)
	mkOp("op-disabled", "bob", models.OperatorStatusDisabled)
	// An OIDC-provisioned account stores the "oidc" sentinel instead of a
	// bcrypt hash (oidc.go), so the real compare fails instantly with
	// ErrHashTooShort — the dummy compare must cover that path too.
	if err := s.CreateOperator(ctx, &models.Operator{
		ID: "op-oidc", Username: "carol", PasswordHash: "oidc", Role: "user",
		Status: models.OperatorStatusActive, AuthProvider: models.OperatorAuthOIDC,
		OIDCIssuer: "https://idp.example.com", OIDCSubject: "carol-sub",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	sm := NewSessionManager(s)

	// Warm up so lazy initialisation does not skew the first measurement.
	_ = bcrypt.CompareHashAndPassword(hash, []byte("warmup"))

	measure := func(user, pass string) time.Duration {
		req := httptest.NewRequest(http.MethodPost, "/ui/login", nil)
		start := time.Now()
		if _, ok, _ := sm.Login(httptest.NewRecorder(), req, user, pass); ok {
			t.Fatalf("login for %q unexpectedly succeeded", user)
		}
		return time.Since(start)
	}
	// The baseline is the genuine-bcrypt path the others are compared
	// against; take the median of three samples so a single scheduler
	// outlier can't skew the floor and flake the test under CI load.
	medianBaseline := func(user, pass string) time.Duration {
		ds := []time.Duration{measure(user, pass), measure(user, pass), measure(user, pass)}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		return ds[1]
	}

	baseline := medianBaseline("alice", "wrong-password") // genuine bcrypt verify (median of 3)
	missing := measure("ghost", "whatever")               // unknown username
	inactive := measure("bob", "whatever")                // disabled account
	oidc := measure("carol", "whatever")                  // active OIDC account ("oidc" sentinel hash)

	floor := baseline / 2
	if missing < floor {
		t.Errorf("unknown-username login too fast: %v < %v (half of baseline %v) — timing oracle for enumeration", missing, floor, baseline)
	}
	if inactive < floor {
		t.Errorf("inactive-account login too fast: %v < %v (half of baseline %v) — timing oracle", inactive, floor, baseline)
	}
	if oidc < floor {
		t.Errorf("OIDC-account login too fast: %v < %v (half of baseline %v) — timing oracle distinguishes OIDC accounts", oidc, floor, baseline)
	}
}
