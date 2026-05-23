package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
)

// createOperatorWithCA creates a non-admin operator with an API key and a CA owned by that operator.
// Returns (plaintext apiKey, operator, ca).
func createOperatorWithCA(t *testing.T, srv *Server) (string, *models.Operator, *models.CA) {
	t.Helper()
	ctx := context.Background()

	// Create non-admin operator
	op := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "user-" + uuid.New().String()[:6],
		PasswordHash: "test-hash",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	err := srv.store.CreateOperator(ctx, op)
	require.NoError(t, err)

	// Create API key for operator
	rawKey := uuid.New().String()
	keySum := sha256.Sum256([]byte(rawKey))
	err = srv.store.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID:         uuid.New().String(),
		OperatorID: op.ID,
		KeyHash:    hex.EncodeToString(keySum[:]),
	})
	require.NoError(t, err)

	// Create CA owned by operator using pki.MintAndStoreCA
	// Requires master keystore and logger (reuse from srv if available, or create minimal ones)
	master := srv.master
	if master == nil {
		// Fallback: create a temporary master for this test
		rawMaster := bytes.Repeat([]byte{0x77}, keystore.MasterKeySize)
		master, err = keystore.NewMaster(rawMaster)
		require.NoError(t, err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ca, _, err := pki.MintAndStoreCA(ctx, srv.store, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "test-ca-" + uuid.New().String()[:6],
		Duration: 365 * 24 * time.Hour,
	})
	require.NoError(t, err)

	return rawKey, op, ca
}

func TestActorOwnsCA_Admin(t *testing.T) {
	srv, st := newTestServer(t)
	ctx := context.Background()

	// seed: actorOwnsCA now re-fetches via isActiveAdmin.
	adminOp := &models.Operator{
		ID:           "admin-op",
		Username:     "admin-test",
		PasswordHash: "hash",
		Role:         "admin",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
	}
	if err := st.CreateOperator(ctx, adminOp); err != nil {
		t.Fatalf("seed admin op: %v", err)
	}
	ctx = context.WithValue(ctx, actorContextKey, adminOp)

	// Get the default CA from newTestServer (owned by test-admin, not admin-op)
	cas, err := st.ListCAs(ctx)
	require.NoError(t, err)
	require.True(t, len(cas) > 0, "should have at least one CA from newTestServer")
	ca := cas[0]

	// Admin should have access to any CA, even one owned by another operator
	ok, err := srv.actorOwnsCA(ctx, ca.ID)
	require.NoError(t, err)
	assert.True(t, ok, "admin should have access to any CA")
}

func TestActorOwnsCA_Owner(t *testing.T) {
	srv, _ := newTestServer(t)
	apiKey, op, ca := createOperatorWithCA(t, srv)

	// Authenticate as owner
	ctx := context.Background()
	ctx = context.WithValue(ctx, actorContextKey, op)

	// Owner should have access
	ok, err := srv.actorOwnsCA(ctx, ca.ID)
	require.NoError(t, err)
	assert.True(t, ok, "owner should have access to owned CA")
	_ = apiKey // prevent unused warning
}

func TestActorOwnsCA_NonOwner(t *testing.T) {
	srv, _ := newTestServer(t)
	_, owner, ca := createOperatorWithCA(t, srv)

	// Create different non-admin operator
	ctx := context.Background()
	other := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "other-user",
		PasswordHash: "hash",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
	}
	err := srv.store.CreateOperator(ctx, other)
	require.NoError(t, err)

	// Other operator should not have access
	ctx = context.WithValue(ctx, actorContextKey, other)
	ok, err := srv.actorOwnsCA(ctx, ca.ID)
	require.NoError(t, err)
	assert.False(t, ok, "non-owner should not have access")
	_ = owner // prevent unused warning
}

func TestActorOwnsCA_EmptyCAID(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	op := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "test-user",
		PasswordHash: "hash",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
	}
	ctx = context.WithValue(ctx, actorContextKey, op)

	// Empty CA ID should return false
	ok, err := srv.actorOwnsCA(ctx, "")
	require.NoError(t, err)
	assert.False(t, ok, "empty caID should return false")
}

func TestActorOwnsCA_CANotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	ctx := context.Background()

	op := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "test-user",
		PasswordHash: "hash",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
	}
	err := srv.store.CreateOperator(ctx, op)
	require.NoError(t, err)

	ctx = context.WithValue(ctx, actorContextKey, op)

	// Non-existent CA should return false without error
	ok, err := srv.actorOwnsCA(ctx, "nonexistent-ca-id")
	require.NoError(t, err)
	assert.False(t, ok, "non-existent CA should return false")
}

func TestCanAccessHost_Owner(t *testing.T) {
	srv, _ := newTestServer(t)
	_, op, ca := createOperatorWithCA(t, srv)

	ctx := context.Background()
	ctx = context.WithValue(ctx, actorContextKey, op)

	// Create host in operator's CA
	host := &models.Host{
		ID:        uuid.New().String(),
		NetworkID: "test-network",
		CAID:      ca.ID,
		Name:      "test-host",
	}

	ok, err := srv.canAccessHost(ctx, host)
	require.NoError(t, err)
	assert.True(t, ok, "owner should have access to host in their CA")
}

func TestCanAccessHost_NonOwner(t *testing.T) {
	srv, _ := newTestServer(t)
	_, op1, ca := createOperatorWithCA(t, srv)

	// Create another operator
	op2 := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "other-user",
		PasswordHash: "hash",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
	}
	err := srv.store.CreateOperator(context.Background(), op2)
	require.NoError(t, err)

	ctx := context.Background()
	ctx = context.WithValue(ctx, actorContextKey, op2)

	// Try to access host in other operator's CA
	host := &models.Host{
		ID:        uuid.New().String(),
		NetworkID: "test-network",
		CAID:      ca.ID,
		Name:      "test-host",
	}

	ok, err := srv.canAccessHost(ctx, host)
	require.NoError(t, err)
	assert.False(t, ok, "non-owner should not have access to host in other's CA")
	_ = op1 // prevent unused warning
}

func TestCanAccessNetwork_Owner(t *testing.T) {
	srv, _ := newTestServer(t)
	_, op, ca := createOperatorWithCA(t, srv)

	ctx := context.Background()
	ctx = context.WithValue(ctx, actorContextKey, op)

	// Create network in operator's CA
	network := &models.Network{
		ID:   uuid.New().String(),
		Name: "test-network",
		CAID: ca.ID,
	}

	ok, err := srv.canAccessNetwork(ctx, network)
	require.NoError(t, err)
	assert.True(t, ok, "owner should have access to network in their CA")
}

func TestCanAccessNetwork_NonOwner(t *testing.T) {
	srv, _ := newTestServer(t)
	_, op1, ca := createOperatorWithCA(t, srv)

	// Create another operator
	op2 := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "other-user",
		PasswordHash: "hash",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
	}
	err := srv.store.CreateOperator(context.Background(), op2)
	require.NoError(t, err)

	ctx := context.Background()
	ctx = context.WithValue(ctx, actorContextKey, op2)

	// Try to access network in other operator's CA
	network := &models.Network{
		ID:   uuid.New().String(),
		Name: "test-network",
		CAID: ca.ID,
	}

	ok, err := srv.canAccessNetwork(ctx, network)
	require.NoError(t, err)
	assert.False(t, ok, "non-owner should not have access to network in other's CA")
	_ = op1 // prevent unused warning
}
