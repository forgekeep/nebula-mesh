package pki_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

func TestRotateAndStoreCA_HappyPath(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	op := seedOperator(t, s, "op-alice", "alice")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Seed an active CA.
	ca1, _, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "alice-default",
		Duration: 10 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err)

	// Rotate it.
	ca2, err := pki.RotateAndStoreCA(context.Background(), s, master, logger, ca1)
	require.NoError(t, err)
	require.NotNil(t, ca2)

	// Assertions.
	assert.NotEqual(t, ca2.ID, ca1.ID)
	assert.NotNil(t, ca2.PredecessorID)
	assert.Equal(t, *ca2.PredecessorID, ca1.ID)
	assert.Equal(t, ca2.Status, models.CAStatusActive)
	assert.NotEmpty(t, ca2.Fingerprint)
	assert.NotEqual(t, ca2.Fingerprint, ca1.Fingerprint)
	assert.Equal(t, ca2.OwnerOperatorID, ca1.OwnerOperatorID)

	// Verify CA duration preserved (within 1 sec tolerance).
	duration1 := ca1.NotAfter.Sub(ca1.NotBefore)
	duration2 := ca2.NotAfter.Sub(ca2.NotBefore)
	assert.WithinDuration(t, ca1.NotAfter, ca2.NotAfter, time.Second)
	assert.WithinDuration(t, ca1.NotBefore, ca2.NotBefore, time.Second)
	assert.Equal(t, duration1, duration2)

	// Verify persisted.
	persisted, err := s.GetCA(context.Background(), ca2.ID)
	require.NoError(t, err)
	assert.Equal(t, persisted.Fingerprint, ca2.Fingerprint)
	assert.NotNil(t, persisted.PredecessorID)
	assert.Equal(t, *persisted.PredecessorID, ca1.ID)

	// Verify audit entry.
	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
	require.NoError(t, err)
	var found bool
	for _, e := range entries {
		if e.Action == "ca.rotated" && e.Resource == ca2.ID {
			found = true
			break
		}
	}
	assert.True(t, found, "audit entry ca.rotated not found")
}

func TestRotateAndStoreCA_IdempotentExistingSuccessor(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	op := seedOperator(t, s, "op-bob", "bob")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Seed CA1.
	ca1, _, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "bob-default",
		Duration: 10 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err)

	// Rotate to CA2.
	ca2, err := pki.RotateAndStoreCA(context.Background(), s, master, logger, ca1)
	require.NoError(t, err)
	require.NotNil(t, ca2)

	// Rotate again (idempotence): should return CA2 without creating CA3.
	ca2Again, err := pki.RotateAndStoreCA(context.Background(), s, master, logger, ca1)
	require.NoError(t, err)
	assert.Equal(t, ca2Again.ID, ca2.ID)

	// Verify DB has exactly 2 CAs.
	all, err := s.ListCAsByOwner(context.Background(), op.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, len(all))
}

func TestRotateAndStoreCA_RequiresMaster(t *testing.T) {
	s := newTestStore(t)
	_ = seedOperator(t, s, "op-charlie", "charlie")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ca := &models.CA{
		ID:     "ca-test",
		Name:   "test",
		Status: models.CAStatusActive,
	}

	_, err := pki.RotateAndStoreCA(context.Background(), s, nil, logger, ca)
	assert.True(t, errors.Is(err, pki.ErrMasterRequired))
}

func TestRotateAndStoreCA_RejectsNonActiveOldCA(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	op := seedOperator(t, s, "op-dave", "dave")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Seed an active CA.
	ca1, _, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "dave-default",
		Duration: 10 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err)

	// Manually retire it.
	ca1.Status = models.CAStatusRetired
	// Simulate a retired CA (normally would be via DB).
	retiredCA := &models.CA{
		ID:     ca1.ID,
		Name:   ca1.Name,
		Status: models.CAStatusRetired,
	}

	// Try to rotate: should fail.
	_, err = pki.RotateAndStoreCA(context.Background(), s, master, logger, retiredCA)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-active")
}

func TestRotateAndStoreCA_RejectsNilOldCA(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	_ = seedOperator(t, s, "op-frank", "frank")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, err := pki.RotateAndStoreCA(context.Background(), s, master, logger, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oldCA")
}

func TestRotateAndStoreCA_PreservesOwner(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	op := seedOperator(t, s, "op-eve", "eve")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Seed an active CA.
	ca1, _, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "eve-default",
		Duration: 10 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err)

	// Rotate it.
	ca2, err := pki.RotateAndStoreCA(context.Background(), s, master, logger, ca1)
	require.NoError(t, err)

	// Verify owner is preserved.
	assert.Equal(t, ca2.OwnerOperatorID, ca1.OwnerOperatorID)
}
