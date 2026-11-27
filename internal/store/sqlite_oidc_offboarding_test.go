package store

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestRevokeOIDCOperator_SEC_PERSIST_001_RollsBackWithAudit(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	op := &models.Operator{
		ID: "federated", Username: "federated", PasswordHash: "oidc", Role: models.OperatorRoleAdmin,
		AuthProvider: models.OperatorAuthOIDC, OIDCIssuer: "https://issuer.example", OIDCSubject: "subject",
	}
	require.NoError(t, s.CreateOperator(ctx, op))
	require.NoError(t, s.CreateOperatorSession(ctx, &models.OperatorSession{
		Token: "previous-session", OperatorID: op.ID, ExpiresAt: time.Now().Add(time.Hour),
	}))
	require.NoError(t, s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: "federated-key", OperatorID: op.ID, Name: "test",
	}, "previous-key"))
	event := &OIDCOffboardingEvent{
		Digest: sha256.Sum256([]byte("previous-event")), ExpiresAt: time.Now().Add(time.Minute),
	}

	_, err := s.db.ExecContext(ctx, `CREATE TRIGGER reject_offboarding_audit
		BEFORE INSERT ON audit_log WHEN NEW.action = 'operator.oidc.revoked'
		BEGIN SELECT RAISE(ABORT, 'offboarding audit unavailable'); END`)
	require.NoError(t, err)
	require.ErrorContains(t, s.RevokeOIDCOperator(ctx, op.OIDCIssuer, op.OIDCSubject, event), "audit OIDC offboarding")
	_, err = s.GetOperatorBySession(ctx, "previous-session")
	require.NoError(t, err)
	_, _, err = s.GetOperatorByAPIKey(ctx, "previous-key")
	require.NoError(t, err)

	_, err = s.db.ExecContext(ctx, `DROP TRIGGER reject_offboarding_audit`)
	require.NoError(t, err)
	require.NoError(t, s.RevokeOIDCOperator(ctx, op.OIDCIssuer, op.OIDCSubject, event))
	_, err = s.GetOperatorBySession(ctx, "previous-session")
	require.ErrorIs(t, err, ErrNotFound)
	key, err := s.GetOperatorAPIKey(ctx, "federated-key")
	require.NoError(t, err)
	require.NotNil(t, key.RevokedAt)
}
