package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestResetOperatorTOTPBreakGlass_SEC_CREDENTIAL_001_IsAtomicAndPreservesStatus(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "totp-reset")
	if err := s.SetOperatorTOTP(ctx, op.ID, "encrypted-or-plain-existing-secret", true); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceOperatorRecoveryCodes(ctx, op.ID, []string{"AAAA-BBBB", "CCCC-DDDD"}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token: "active-session", OperatorID: op.ID, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE operators SET status = ? WHERE id = ?`,
		models.OperatorStatusDisabled, op.ID); err != nil {
		t.Fatal(err)
	}

	if err := s.ResetOperatorTOTPBreakGlass(ctx, op.Username); err != nil {
		t.Fatalf("ResetOperatorTOTPBreakGlass(): %v", err)
	}

	var secret, status string
	var enabled int
	var timestep int64
	if err := s.db.QueryRowContext(ctx,
		`SELECT totp_secret, totp_enabled, totp_last_timestep, status FROM operators WHERE id = ?`, op.ID).
		Scan(&secret, &enabled, &timestep, &status); err != nil {
		t.Fatal(err)
	}
	if secret != "" || enabled != 0 || timestep != 0 {
		t.Fatalf("TOTP state after reset = secret %q enabled %d timestep %d", secret, enabled, timestep)
	}
	if models.OperatorStatus(status) != models.OperatorStatusDisabled {
		t.Fatalf("operator status = %q, want disabled", status)
	}
	for _, table := range []string{"operator_recovery_codes", "operator_sessions"} {
		var count int
		if err := s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+table+` WHERE operator_id = ?`, op.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Errorf("%s rows = %d, want 0", table, count)
		}
	}
	var audits int
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM audit_log
		WHERE actor = 'ops-cli-break-glass'
		  AND action = 'operator.totp.reset'
		  AND resource = ?`, op.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("audit rows = %d, want 1", audits)
	}
}

func TestResetOperatorTOTPBreakGlass_SEC_CREDENTIAL_001_RollsBackOnAuditFailure(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	op := newTestOperator(t, s, "totp-rollback")
	if err := s.SetOperatorTOTP(ctx, op.ID, "secret", true); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceOperatorRecoveryCodes(ctx, op.ID, []string{"AAAA-BBBB"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `
		CREATE TRIGGER fail_totp_reset_audit
		BEFORE INSERT ON audit_log
		WHEN NEW.action = 'operator.totp.reset'
		BEGIN
			SELECT RAISE(ABORT, 'injected audit failure');
		END`); err != nil {
		t.Fatal(err)
	}

	if err := s.ResetOperatorTOTPBreakGlass(ctx, op.Username); err == nil {
		t.Fatal("ResetOperatorTOTPBreakGlass() succeeded despite audit failure")
	}
	got, err := s.GetOperator(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TOTPEnabled || got.TOTPSecret != "secret" {
		t.Fatalf("TOTP state was partially reset: %#v", got)
	}
	codes, err := s.ListOperatorRecoveryCodes(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 1 {
		t.Fatalf("recovery codes after rollback = %d, want 1", len(codes))
	}
}

func TestResetOperatorTOTPBreakGlass_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.ResetOperatorTOTPBreakGlass(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}
