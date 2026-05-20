package pki_test

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
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

// Compile-time check: store.Store satisfies pki.MintStore.
var _ pki.MintStore = (store.Store)(nil)

func newTestMaster(t *testing.T) *keystore.Master {
	t.Helper()
	raw := bytes.Repeat([]byte{0x77}, keystore.MasterKeySize)
	m, err := keystore.NewMaster(raw)
	if err != nil {
		t.Fatalf("NewMaster: %v", err)
	}
	return m
}

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func seedOperator(t *testing.T, s store.Store, id, username string) *models.Operator {
	t.Helper()
	op := &models.Operator{
		ID:           id,
		Username:     username,
		DisplayName:  username,
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(context.Background(), op); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	return op
}

func TestMintAndStoreCA_HappyPath(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	op := seedOperator(t, s, "op-alice", "alice")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ca, minted, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "alice-default",
		Duration: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("MintAndStoreCA: %v", err)
	}
	if !minted {
		t.Errorf("minted = false, want true")
	}
	if ca == nil {
		t.Fatal("ca is nil")
		return
	}
	if ca.Name != "alice-default" {
		t.Errorf("Name = %q, want alice-default", ca.Name)
	}
	if ca.OwnerOperatorID != op.ID {
		t.Errorf("OwnerOperatorID = %q, want %q", ca.OwnerOperatorID, op.ID)
	}
	if ca.Status != models.CAStatusActive {
		t.Errorf("Status = %q, want %q", ca.Status, models.CAStatusActive)
	}
	if ca.Fingerprint == "" {
		t.Error("Fingerprint is empty")
	}
	if len(ca.EncryptedKeyDEK) == 0 || len(ca.NonceDEK) == 0 {
		t.Error("EncryptedKeyDEK/NonceDEK is empty")
	}
	if len(ca.EncryptedKeyMaterial) == 0 || len(ca.NonceKey) == 0 {
		t.Error("EncryptedKeyMaterial/NonceKey is empty")
	}

	persisted, err := s.GetCA(context.Background(), ca.ID)
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if persisted.Fingerprint != ca.Fingerprint {
		t.Errorf("persisted Fingerprint = %q, want %q", persisted.Fingerprint, ca.Fingerprint)
	}

	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatalf("ListAuditEntries: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "ca.created" && e.Resource == ca.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit entry ca.created not found")
	}
}

func TestMintAndStoreCA_SkipIfActive_ReturnsExisting(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	op := seedOperator(t, s, "op-bob", "bob")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	first, _, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "bob-default",
		Duration: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("first MintAndStoreCA: %v", err)
	}

	second, minted, err := pki.MintAndStoreCA(context.Background(), s, master, logger, pki.MintRequest{
		Operator:     op,
		Name:         "bob-default",
		Duration:     10 * 365 * 24 * time.Hour,
		SkipIfActive: true,
	})
	if err != nil {
		t.Fatalf("second MintAndStoreCA: %v", err)
	}
	if minted {
		t.Error("minted = true on second call with SkipIfActive, want false")
	}
	if second.ID != first.ID {
		t.Errorf("second.ID = %q, want %q (existing)", second.ID, first.ID)
	}

	all, err := s.ListCAsByOwner(context.Background(), op.ID)
	if err != nil {
		t.Fatalf("ListCAsByOwner: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("len(ListCAsByOwner) = %d, want 1", len(all))
	}
}

func TestMintAndStoreCA_NilMaster_ReturnsError(t *testing.T) {
	s := newTestStore(t)
	op := seedOperator(t, s, "op-charlie", "charlie")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	_, minted, err := pki.MintAndStoreCA(context.Background(), s, nil, logger, pki.MintRequest{
		Operator: op,
		Name:     "charlie-default",
		Duration: 10 * 365 * 24 * time.Hour,
	})
	if !errors.Is(err, pki.ErrMasterRequired) {
		t.Errorf("err = %v, want ErrMasterRequired", err)
	}
	if minted {
		t.Error("minted = true on nil master, want false")
	}
}

type errStore struct {
	store.Store
	createErr error
}

func (e *errStore) CreateCA(ctx context.Context, c *models.CA) error {
	return e.createErr
}

func TestMintAndStoreCA_StoreError_Propagates(t *testing.T) {
	s := newTestStore(t)
	master := newTestMaster(t)
	op := seedOperator(t, s, "op-dave", "dave")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	wrapper := &errStore{Store: s, createErr: errors.New("disk full")}

	_, minted, err := pki.MintAndStoreCA(context.Background(), wrapper, master, logger, pki.MintRequest{
		Operator: op,
		Name:     "dave-default",
		Duration: 10 * 365 * 24 * time.Hour,
	})
	if err == nil {
		t.Fatal("err = nil, want non-nil")
	}
	if !errors.Is(err, wrapper.createErr) {
		// errors.Is should work via fmt.Errorf("%w", ...)
		t.Errorf("err = %v; expected wrapped %v", err, wrapper.createErr)
	}
	if minted {
		t.Error("minted = true on store error, want false")
	}
}
