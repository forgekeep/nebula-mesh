package api

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestCAForHost_ResolvesCAID(t *testing.T) {
	ctx := context.Background()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// Create a CA and seed resolver
	master, err := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	op := &models.Operator{
		ID:           "op1",
		Username:     "testop",
		PasswordHash: "hash",
		Role:         "admin",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}

	ca, _, err := pki.MintAndStoreCA(ctx, s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "test-ca",
		Duration: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create server with resolver
	srv, _ := newTestServer(t)
	srv.WithCAResolver(pki.NewCAResolver(s, master))

	// Test: host with CAID resolves correctly
	host := &models.Host{ID: "host1", CAID: ca.ID}
	resolved, err := srv.caForHost(ctx, host)
	if err != nil {
		t.Fatalf("caForHost failed: %v", err)
	}
	if resolved == nil {
		t.Fatalf("resolved CA is nil")
	}
}

func TestCAForHost_RejectsEmptyCAID(t *testing.T) {
	ctx := context.Background()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	master, err := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}

	srv, _ := newTestServer(t)
	srv.WithCAResolver(pki.NewCAResolver(s, master))

	// Test: host with empty CAID returns error
	host := &models.Host{ID: "host1", CAID: ""}
	_, err = srv.caForHost(ctx, host)
	if err == nil {
		t.Fatalf("expected error for empty CAID, got nil")
	}
}

func TestCAForHost_RejectsUnknownCAID(t *testing.T) {
	ctx := context.Background()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	master, err := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}

	srv, _ := newTestServer(t)
	srv.WithCAResolver(pki.NewCAResolver(s, master))

	// Test: host with unknown CAID returns error from resolver
	host := &models.Host{ID: "host1", CAID: "nonexistent"}
	_, err = srv.caForHost(ctx, host)
	if err == nil {
		t.Fatalf("expected error for unknown CAID, got nil")
	}
}
