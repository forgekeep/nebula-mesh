package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

// SEC-CREDENTIAL-001: promotion persists only the new purpose-separated keyed
// verifier and leaves no usable copy of either raw bearer in the database.
func TestPromoteOperatorSession_SEC_PERSIST_001_RotatesKeyedVerifier(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "dave")

	const (
		pending = "pending-session-token"
		rotated = "rotated-authenticated-session-token"
	)
	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token:      pending,
		OperatorID: op.ID,
		State:      models.SessionStatePendingTOTP,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create pending session: %v", err)
	}

	if err := s.PromoteOperatorSession(ctx, pending, rotated, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("promote session: %v", err)
	}
	if _, err := s.GetOperatorBySession(ctx, pending); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old bearer lookup err = %v, want ErrNotFound", err)
	}
	got, err := s.GetOperatorBySession(ctx, rotated)
	if err != nil {
		t.Fatalf("new bearer lookup: %v", err)
	}
	if got.ID != op.ID {
		t.Fatalf("new bearer operator = %q, want %q", got.ID, op.ID)
	}

	stored, err := s.credentialDigest(credentialhash.PurposeOperatorSession, rotated)
	if err != nil {
		t.Fatalf("derive rotated verifier: %v", err)
	}
	var count int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM operator_sessions WHERE token_hash=?`, stored).Scan(&count); err != nil {
		t.Fatalf("read rotated verifier: %v", err)
	}
	if count != 1 {
		t.Fatalf("rotated keyed verifier rows = %d, want 1", count)
	}
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM operator_sessions WHERE token_hash IN (?, ?)`, pending, rotated).Scan(&count); err != nil {
		t.Fatalf("count raw bearer rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("raw bearer rows = %d, want 0", count)
	}

	if err := s.PromoteOperatorSession(ctx, rotated, "second-rotation", time.Now().Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("authenticated session promotion err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetOperatorBySession(ctx, rotated); err != nil {
		t.Fatalf("failed repeat promotion changed authenticated session: %v", err)
	}
}

// TestCreateOperatorSession_StoresHMACNotRaw covers SEC-CREDENTIAL-001: the
// session token must be persisted as its keyed verifier, never as the raw value
// that travels in the cookie. A DB read (backup/snapshot) must not yield a
// usable session token.
func TestCreateOperatorSession_StoresHMACNotRaw(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "dave")

	const raw = "raw-session-token-deadbeef"
	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token:      raw,
		OperatorID: op.ID,
		ExpiresAt:  time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// At rest the column holds the hash, not the raw token.
	var stored string
	if err := s.db.QueryRowContext(ctx,
		`SELECT token_hash FROM operator_sessions WHERE operator_id=?`, op.ID).Scan(&stored); err != nil {
		t.Fatalf("read token_hash: %v", err)
	}
	want, err := s.credentialDigest(credentialhash.PurposeOperatorSession, raw)
	if err != nil {
		t.Fatalf("derive expected verifier: %v", err)
	}
	if stored != want {
		t.Errorf("stored token_hash = %q, want %q", stored, want)
	}
	if stored == raw {
		t.Error("raw session token persisted verbatim at rest")
	}

	// No row anywhere holds the raw token value.
	var rawRows int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM operator_sessions WHERE token_hash=?`, raw).Scan(&rawRows); err != nil {
		t.Fatalf("count raw rows: %v", err)
	}
	if rawRows != 0 {
		t.Errorf("found %d rows storing the raw token", rawRows)
	}

	// Lookup by the raw token (as carried in the cookie) still works.
	got, err := s.GetOperatorBySession(ctx, raw)
	if err != nil {
		t.Fatalf("lookup by raw token: %v", err)
	}
	if got.ID != op.ID {
		t.Errorf("session resolved to %q, want %q", got.ID, op.ID)
	}

	// A wrong token does not resolve.
	if _, err := s.GetOperatorBySession(ctx, "not-the-token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong token err = %v, want ErrNotFound", err)
	}
}
