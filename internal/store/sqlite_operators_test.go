package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
)

func newTestOperator(t *testing.T, s *SQLiteStore, username string) *models.Operator {
	t.Helper()
	op := &models.Operator{
		ID:           "op-" + username,
		Username:     username,
		DisplayName:  username,
		PasswordHash: "bcrypt$hash$" + username,
	}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	return op
}

func TestCreateOperator_Defaults(t *testing.T) {
	s := newTestStore(t)
	op := newTestOperator(t, s, "alice")

	got, err := s.GetOperator(context.Background(), op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.OperatorStatusActive {
		t.Errorf("status = %q, want active", got.Status)
	}
	if got.AuthProvider != models.OperatorAuthLocal {
		t.Errorf("auth_provider = %q, want local", got.AuthProvider)
	}
	if got.Role != "admin" {
		t.Errorf("role = %q, want admin", got.Role)
	}
}

func TestGetOperatorByUsername(t *testing.T) {
	s := newTestStore(t)
	op := newTestOperator(t, s, "bob")

	got, err := s.GetOperatorByUsername(context.Background(), "bob")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != op.ID {
		t.Errorf("id = %q, want %q", got.ID, op.ID)
	}

	if _, err := s.GetOperatorByUsername(context.Background(), "nobody"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestDisableOperator_CascadesSessionsAndAPIKeys(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "carol")

	// One API key, one session
	if err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: "k1", OperatorID: op.ID, Name: "cli", KeyHash: "hash1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token: "tok1", OperatorID: op.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.DisableOperator(ctx, op.ID); err != nil {
		t.Fatal(err)
	}

	// Status disabled
	got, _ := s.GetOperator(ctx, op.ID)
	if got.Status != models.OperatorStatusDisabled {
		t.Errorf("status = %q, want disabled", got.Status)
	}

	// Sessions gone
	if _, err := s.GetOperatorBySession(ctx, "tok1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("session still valid after disable: %v", err)
	}

	// API keys revoked
	keys, _ := s.ListOperatorAPIKeys(ctx, op.ID)
	if len(keys) != 1 {
		t.Fatalf("keys len = %d", len(keys))
	}
	if keys[0].RevokedAt == nil {
		t.Error("api key not revoked after disable")
	}

	// Lookup by hash returns nothing (revoked + operator disabled)
	if _, _, err := s.GetOperatorByAPIKeyHash(ctx, "hash1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("disabled operator's key still resolves: %v", err)
	}
}

func TestGetOperatorByAPIKeyHash_Lookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "dave")
	if err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: "k-dave", OperatorID: op.ID, Name: "main", KeyHash: "dave-hash",
	}); err != nil {
		t.Fatal(err)
	}

	gotOp, gotKey, err := s.GetOperatorByAPIKeyHash(ctx, "dave-hash")
	if err != nil {
		t.Fatal(err)
	}
	if gotOp.ID != op.ID {
		t.Errorf("operator id = %q, want %q", gotOp.ID, op.ID)
	}
	if gotKey.Name != "main" {
		t.Errorf("key name = %q, want main", gotKey.Name)
	}

	if _, _, err := s.GetOperatorByAPIKeyHash(ctx, "nonexistent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestRevokeOperatorAPIKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "eve")
	if err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: "k-eve", OperatorID: op.ID, KeyHash: "eve-hash",
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeOperatorAPIKey(ctx, "k-eve"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.GetOperatorByAPIKeyHash(ctx, "eve-hash"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked key still resolves: %v", err)
	}

	if err := s.RevokeOperatorAPIKey(ctx, "k-eve"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound on second revoke", err)
	}
}

// TestGetOperatorAPIKey covers the new ownership-verification lookup.
// The method must return the row regardless of revoked state — callers
// that need to verify kid-belongs-to-id compare key.OperatorID without
// caring whether the key is still active.
func TestGetOperatorAPIKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "grace")
	if err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: "k-grace", OperatorID: op.ID, Name: "primary", KeyHash: "grace-hash",
	}); err != nil {
		t.Fatal(err)
	}

	t.Run("active_key_returns", func(t *testing.T) {
		got, err := s.GetOperatorAPIKey(ctx, "k-grace")
		if err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		if got.ID != "k-grace" || got.OperatorID != op.ID {
			t.Errorf("got = %+v, want id=k-grace operator_id=%s", got, op.ID)
		}
		if got.RevokedAt != nil {
			t.Errorf("revoked_at = %v, want nil for active key", got.RevokedAt)
		}
	})

	t.Run("revoked_key_still_returns", func(t *testing.T) {
		if err := s.RevokeOperatorAPIKey(ctx, "k-grace"); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetOperatorAPIKey(ctx, "k-grace")
		if err != nil {
			t.Fatalf("err = %v, want nil (revoked keys must still resolve for ownership check)", err)
		}
		if got.RevokedAt == nil {
			t.Errorf("revoked_at = nil, want non-nil after revoke")
		}
		if got.OperatorID != op.ID {
			t.Errorf("operator_id = %q, want %q (must survive revoke)", got.OperatorID, op.ID)
		}
	})

	t.Run("missing_key_returns_ErrNotFound", func(t *testing.T) {
		_, err := s.GetOperatorAPIKey(ctx, "k-does-not-exist")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("err = %v, want ErrNotFound", err)
		}
	})
}

func TestSessionLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "frank")

	exp := time.Now().Add(time.Hour)
	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token: "frank-tok", OperatorID: op.ID, ExpiresAt: exp,
	}); err != nil {
		t.Fatal(err)
	}

	got, err := s.GetOperatorBySession(ctx, "frank-tok")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != op.ID {
		t.Errorf("operator id = %q, want %q", got.ID, op.ID)
	}

	if err := s.DeleteOperatorSession(ctx, "frank-tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetOperatorBySession(ctx, "frank-tok"); !errors.Is(err, ErrNotFound) {
		t.Errorf("session still valid after delete: %v", err)
	}
}

func TestDeleteExpiredOperatorSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "gina")

	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token: "old", OperatorID: op.ID, ExpiresAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token: "fresh", OperatorID: op.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteExpiredOperatorSessions(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetOperatorBySession(ctx, "fresh"); err != nil {
		t.Errorf("fresh session removed: %v", err)
	}
	if _, err := s.GetOperatorBySession(ctx, "old"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old session still present: %v", err)
	}
}
