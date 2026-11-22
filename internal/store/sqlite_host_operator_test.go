package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// SEC-TENANT-001: an operator read uses the host's CA and the durable actor
// status, including for the otherwise unrestricted admin role.
func TestGetHostForOperatorUsesCurrentHostScope(t *testing.T) {
	s, owner, other, admin, h := seedHostOperatorScope(t)
	ctx := t.Context()
	got, err := s.GetHostForOperator(ctx, owner, h.ID)
	require.NoError(t, err)
	require.Equal(t, h.Name, got.Name)
	require.Equal(t, h.NebulaIPs, got.NebulaIPs)
	got, err = s.GetHostForOperator(ctx, admin, h.ID)
	require.NoError(t, err)
	require.Equal(t, h.ID, got.ID)
	for _, denied := range []string{"", "unknown-operator", other} {
		got, err := s.GetHostForOperator(ctx, denied, h.ID)
		require.ErrorIs(t, err, ErrHostAccessDenied)
		require.Nil(t, got)
	}
	require.NoError(t, s.DisableOperator(ctx, owner))
	got, err = s.GetHostForOperator(ctx, owner, h.ID)
	require.ErrorIs(t, err, ErrHostAccessDenied)
	require.Nil(t, got)
	got, err = s.GetHostForOperator(ctx, admin, "missing-host")
	require.ErrorIs(t, err, ErrNotFound)
	require.Nil(t, got)
	require.NoError(t, s.DisableOperator(ctx, admin))
	got, err = s.GetHostForOperator(ctx, admin, h.ID)
	require.ErrorIs(t, err, ErrHostAccessDenied)
	require.Nil(t, got)
}

// SEC-TENANT-001: denied blocks leave both the host and its published
// certificate policy untouched; the active owner or admin can still block.
func TestBlockHostForOperatorUsesCurrentHostScope(t *testing.T) {
	for _, role := range []string{"owner", "admin"} {
		t.Run(role, func(t *testing.T) {
			s, owner, other, admin, h := seedHostOperatorScope(t)
			ctx := t.Context()
			version, err := s.GetNetworkConfigVersion(ctx, h.NetworkID)
			require.NoError(t, err)
			for _, denied := range []string{"", "unknown-operator", other} {
				got, err := s.BlockHostForOperator(ctx, denied, h.ID, "fixture block")
				require.ErrorIs(t, err, ErrHostAccessDenied)
				require.Nil(t, got)
			}
			if role == "admin" {
				require.NoError(t, s.DisableOperator(ctx, owner))
				got, err := s.BlockHostForOperator(ctx, owner, h.ID, "fixture block")
				require.ErrorIs(t, err, ErrHostAccessDenied)
				require.Nil(t, got)
				owner = admin
			}
			unchanged, err := s.GetHost(ctx, h.ID)
			require.NoError(t, err)
			require.Equal(t, models.HostStatusEnrolled, unchanged.Status)
			current, err := s.GetNetworkConfigVersion(ctx, h.NetworkID)
			require.NoError(t, err)
			require.Equal(t, version, current)
			var revoked bool
			require.NoError(t, s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM blocklist WHERE fingerprint = ?)`, h.CertFingerprint).Scan(&revoked))
			require.False(t, revoked)
			got, err := s.BlockHostForOperator(ctx, owner, h.ID, "fixture block")
			require.NoError(t, err)
			require.Equal(t, models.HostStatusBlocked, got.Status)
			current, err = s.GetNetworkConfigVersion(ctx, h.NetworkID)
			require.NoError(t, err)
			require.Equal(t, version+1, current)
			require.NoError(t, s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM blocklist WHERE fingerprint = ?)`, h.CertFingerprint).Scan(&revoked))
			require.True(t, revoked)
		})
	}
}

func seedHostOperatorScope(t *testing.T) (s *SQLiteStore, owner, other, admin string, h *models.Host) {
	t.Helper()
	fixture := newCAScopedVersionFixture(t)
	s, h = fixture.store, fixture.host
	ca, err := s.GetCA(t.Context(), h.CAID)
	require.NoError(t, err)
	for _, op := range []models.Operator{
		{ID: "other-host-operator", Role: models.OperatorRoleUser},
		{ID: "admin-host-operator", Role: models.OperatorRoleAdmin},
	} {
		op.Username = op.ID
		op.PasswordHash = "unused-fixture-hash"
		op.Status = models.OperatorStatusActive
		op.AuthProvider = models.OperatorAuthLocal
		op.CreatedAt, op.UpdatedAt = time.Now(), time.Now()
		require.NoError(t, s.CreateOperator(t.Context(), &op))
	}
	return s, ca.OwnerOperatorID, "other-host-operator", "admin-host-operator", h
}
