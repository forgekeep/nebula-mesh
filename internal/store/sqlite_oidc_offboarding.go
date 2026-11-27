package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// OIDCOffboardingEvent carries the identity and deadline of an authenticated
// webhook delivery. A nil event denotes a denial from a verified login callback.
type OIDCOffboardingEvent struct {
	Digest    [32]byte
	ExpiresAt time.Time
}

// RevokeOIDCOperator disables only the named federated identity. Credential
// revocation, audit, and webhook replay protection commit together.
func (s *SQLiteStore) RevokeOIDCOperator(ctx context.Context, issuer, subject string, event *OIDCOffboardingEvent) error {
	if issuer == "" || subject == "" {
		return errors.New("OIDC issuer and subject are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin OIDC offboarding: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			slog.Error("rollback OIDC offboarding", "error", err)
		}
	}()

	now := time.Now()
	var id string
	err = tx.QueryRowContext(ctx, `UPDATE operators SET status = ?, updated_at = ?
		WHERE auth_provider = ? AND oidc_issuer = ? AND oidc_subject = ? AND status = ?
		RETURNING id`, models.OperatorStatusDisabled, now, models.OperatorAuthOIDC,
		issuer, subject, models.OperatorStatusActive).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return tx.Commit()
	}
	if err != nil {
		return fmt.Errorf("disable federated operator: %w", err)
	}
	source := "claims"
	auditID := ""
	if event != nil {
		if !event.ExpiresAt.After(time.Now()) {
			return nil
		}
		source = "webhook"
		auditID = "audit_oidc_" + hex.EncodeToString(event.Digest[:])
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO audit_log (id, actor, action, resource, details)
		VALUES (COALESCE(NULLIF(?, ''), 'audit_' || lower(hex(randomblob(16)))),
		        'oidc-idp', 'operator.oidc.revoked', ?, ?)
		ON CONFLICT(id) DO NOTHING`, auditID, id, "source="+source)
	if err != nil {
		return fmt.Errorf("audit OIDC offboarding: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count OIDC offboarding audit rows: %w", err)
	}
	if n == 0 {
		if event == nil {
			return errors.New("duplicate OIDC offboarding audit ID")
		}
		// The original audit row is the durable event receipt.
		return nil
	}
	if err := revokeOperatorCredentials(ctx, tx, id, now); err != nil {
		return err
	}
	return tx.Commit()
}
