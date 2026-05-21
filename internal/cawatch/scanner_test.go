package cawatch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

func newTestStore(t *testing.T) (store.Store, string) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Create a test operator
	ctx := context.Background()
	op := &models.Operator{
		ID:           "test-op",
		Username:     "testop",
		PasswordHash: "hash",
		Status:       models.OperatorStatusActive,
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatalf("create operator: %v", err)
	}

	return s, op.ID
}

func TestScanner_Run_RotatesApproachingExpiry(t *testing.T) {
	ctx := context.Background()
	st, opID := newTestStore(t)

	// Create two CAs: one fresh, one approaching expiry
	now := time.Now()
	fresh := &models.CA{
		ID:                   "fresh",
		Name:                 "Fresh CA",
		OwnerOperatorID:      opID,
		Fingerprint:          "fp_fresh",
		Status:               models.CAStatusActive,
		NotBefore:            now.AddDate(0, 0, -30),
		NotAfter:             now.AddDate(10, 0, 0), // 10 years, lots of life left
		CertPEM:              "-----BEGIN NEBULA CERTIFICATE-----\nfresh\n-----END NEBULA CERTIFICATE-----\n",
		EncryptedKeyDEK:      []byte("key"),
		NonceDEK:             []byte("nonce"),
		EncryptedKeyMaterial: []byte("material"),
		NonceKey:             []byte("nonce_key"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := st.CreateCA(ctx, fresh); err != nil {
		t.Fatalf("create fresh CA: %v", err)
	}

	// CA approaching expiry: 20% lifetime remaining
	approaching := &models.CA{
		ID:                   "approaching",
		Name:                 "Approaching CA",
		OwnerOperatorID:      opID,
		Fingerprint:          "fp_approaching",
		Status:               models.CAStatusActive,
		NotBefore:            now.AddDate(-10, 0, 0),            // 10 years old
		NotAfter:             now.Add(365 * 24 * time.Hour * 2), // ~2 years left = 20% of 10-year lifetime
		CertPEM:              "-----BEGIN NEBULA CERTIFICATE-----\napproaching\n-----END NEBULA CERTIFICATE-----\n",
		EncryptedKeyDEK:      []byte("key"),
		NonceDEK:             []byte("nonce"),
		EncryptedKeyMaterial: []byte("material"),
		NonceKey:             []byte("nonce_key"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := st.CreateCA(ctx, approaching); err != nil {
		t.Fatalf("create approaching CA: %v", err)
	}

	// Create master key
	master, _ := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create scanner with 20% threshold
	scanner := &Scanner{
		Store:     st,
		Master:    master,
		Logger:    logger,
		Threshold: 0.20,
		Interval:  5 * time.Minute, // not used in Run()
	}

	// Run scanner
	if err := scanner.Run(ctx); err != nil {
		t.Fatalf("scanner.Run: %v", err)
	}

	// Verify approaching CA was rotated (has successor)
	successor, err := st.FindCAByPredecessor(ctx, approaching.ID)
	if err != nil {
		t.Fatalf("FindCAByPredecessor: %v", err)
	}
	if successor == nil {
		t.Fatal("scanner did not create successor for approaching CA")
		return
	}
	if successor.PredecessorID == nil || *successor.PredecessorID != approaching.ID {
		t.Errorf("successor.PredecessorID = %v, want %q", successor.PredecessorID, approaching.ID)
	}

	// Verify fresh CA was NOT rotated (no successor)
	freshSuccessor, err := st.FindCAByPredecessor(ctx, fresh.ID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("fresh CA should have no successor, got err=%v", err)
	}
	if freshSuccessor != nil {
		t.Errorf("fresh CA was rotated, but should not have been")
	}
}

func TestScanner_Run_IdempotentOnSecondCall(t *testing.T) {
	ctx := context.Background()
	st, opID := newTestStore(t)

	now := time.Now()
	approaching := &models.CA{
		ID:                   "approaching",
		Name:                 "Approaching CA",
		OwnerOperatorID:      opID,
		Fingerprint:          "fp_approaching",
		Status:               models.CAStatusActive,
		NotBefore:            now.AddDate(-10, 0, 0),
		NotAfter:             now.Add(365 * 24 * time.Hour * 2),
		CertPEM:              "-----BEGIN NEBULA CERTIFICATE-----\napproaching\n-----END NEBULA CERTIFICATE-----\n",
		EncryptedKeyDEK:      []byte("key"),
		NonceDEK:             []byte("nonce"),
		EncryptedKeyMaterial: []byte("material"),
		NonceKey:             []byte("nonce_key"),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := st.CreateCA(ctx, approaching); err != nil {
		t.Fatalf("create CA: %v", err)
	}

	master, _ := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	scanner := &Scanner{
		Store:     st,
		Master:    master,
		Logger:    logger,
		Threshold: 0.20,
		Interval:  5 * time.Minute,
	}

	// First run
	if err := scanner.Run(ctx); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	successor1, err := st.FindCAByPredecessor(ctx, approaching.ID)
	if err != nil {
		t.Fatalf("FindCAByPredecessor after first run: %v", err)
	}
	if successor1 == nil {
		t.Fatal("first run did not create successor")
		return
	}

	// Second run
	if err := scanner.Run(ctx); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	// Verify same successor (idempotent)
	successor2, err := st.FindCAByPredecessor(ctx, approaching.ID)
	if err != nil {
		t.Fatalf("FindCAByPredecessor after second run: %v", err)
	}
	if successor2.ID != successor1.ID {
		t.Errorf("second run created different successor: %q vs %q", successor2.ID, successor1.ID)
	}
}

func TestScanner_StartLoop_StopsOnCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	st, _ := newTestStore(t)

	master, _ := keystore.NewMaster(bytes.Repeat([]byte{0x77}, keystore.MasterKeySize))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	scanner := &Scanner{
		Store:     st,
		Master:    master,
		Logger:    logger,
		Threshold: 0.20,
		Interval:  10 * time.Millisecond, // fast tick for test
	}

	// Start loop in goroutine
	done := make(chan struct{})
	go func() {
		scanner.StartLoop(ctx)
		close(done)
	}()

	// Give it a moment to start
	time.Sleep(5 * time.Millisecond)

	// Cancel context
	cancel()

	// Verify loop stops within reasonable time
	select {
	case <-done:
		// Success
	case <-time.After(1 * time.Second):
		t.Fatal("StartLoop did not stop after context cancel")
	}
}
