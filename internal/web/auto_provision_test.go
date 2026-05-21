package web

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// newOperatorsWebWithMaster creates a Web with a configured master keystore
// for CA-minting tests. Mirrors the pattern from internal/api/cas_test.go.
func newOperatorsWebWithMaster(t *testing.T) (*Web, store.Store) {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	w, err := New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	// Wire a master keystore.
	raw := bytes.Repeat([]byte{0x77}, keystore.MasterKeySize)
	master, err := keystore.NewMaster(raw)
	if err != nil {
		t.Fatal(err)
	}
	w.WithMaster(master)

	return w, s
}

func TestProvisionDefaultCA_HappyPath(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	ctx := context.Background()

	// Create a user operator.
	op := &models.Operator{
		ID:           "op-alice",
		Username:     "alice",
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}

	// Provision default CA.
	err := w.provisionDefaultCA(ctx, op)
	if err != nil {
		t.Fatalf("provisionDefaultCA = %v, want nil", err)
	}

	// Verify CA was created.
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Fatalf("ListCAsByOwner returned %d CA(s), want 1", len(cas))
	}

	ca := cas[0]
	if ca.Name != "alice-default" {
		t.Errorf("CA name = %q, want alice-default", ca.Name)
	}
	if ca.Status != models.CAStatusActive {
		t.Errorf("CA status = %q, want %q", ca.Status, models.CAStatusActive)
	}
	if ca.Fingerprint == "" {
		t.Error("CA fingerprint is empty")
	}
	if ca.OwnerOperatorID != op.ID {
		t.Errorf("CA owner = %q, want %q", ca.OwnerOperatorID, op.ID)
	}

	// Verify audit entry.
	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action == "ca.created" && entry.Resource == ca.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit entry for ca.created not found")
	}
}

func TestProvisionDefaultCA_SkipsWhenMasterNil(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	w, err := New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Do NOT call WithMaster — leave w.caMaster as nil.

	ctx := context.Background()
	op := &models.Operator{
		ID:           "op-bob",
		Username:     "bob",
		PasswordHash: "x",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}

	// provisionDefaultCA should return nil (graceful skip).
	err = w.provisionDefaultCA(ctx, op)
	if err != nil {
		t.Fatalf("provisionDefaultCA with nil master = %v, want nil", err)
	}

	// Verify no CA was created.
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 0 {
		t.Fatalf("ListCAsByOwner returned %d CA(s), want 0", len(cas))
	}
}

func TestProvisionDefaultCA_IdempotentWhenAlreadyHasCA(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	ctx := context.Background()

	op := &models.Operator{
		ID:           "op-charlie",
		Username:     "charlie",
		PasswordHash: "x",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}

	// Seed an existing active CA.
	existingCA := &models.CA{
		ID:                   "ca-existing",
		Name:                 "charlie-existing",
		OwnerOperatorID:      op.ID,
		Fingerprint:          "fp-existing",
		Status:               models.CAStatusActive,
		NotAfter:             time.Now().Add(time.Hour),
		EncryptedKeyDEK:      []byte("d"),
		NonceDEK:             []byte("nd"),
		EncryptedKeyMaterial: []byte("k"),
		NonceKey:             []byte("nk"),
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}
	if err := s.CreateCA(ctx, existingCA); err != nil {
		t.Fatal(err)
	}

	// Provision default CA should skip (idempotence).
	err := w.provisionDefaultCA(ctx, op)
	if err != nil {
		t.Fatalf("provisionDefaultCA = %v, want nil", err)
	}

	// Verify still only 1 CA.
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Fatalf("ListCAsByOwner returned %d CA(s), want 1", len(cas))
	}
	if cas[0].ID != "ca-existing" {
		t.Errorf("CA ID = %q, want ca-existing (should not have duplicated)", cas[0].ID)
	}
}

func TestProvisionDefaultCA_AutoProvisionsForAdminRole(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	ctx := context.Background()

	op := &models.Operator{
		ID:           "op-admin",
		Username:     "admin",
		PasswordHash: "x",
		Role:         "admin",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}

	// Provision for admin should auto-provision default CA.
	err := w.provisionDefaultCA(ctx, op)
	if err != nil {
		t.Fatalf("provisionDefaultCA for admin = %v, want nil", err)
	}

	// Verify CA was created.
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 {
		t.Fatalf("ListCAsByOwner returned %d CA(s), want 1", len(cas))
	}

	ca := cas[0]
	if ca.Name != "admin-default" {
		t.Errorf("CA name = %q, want admin-default", ca.Name)
	}
	if ca.Status != models.CAStatusActive {
		t.Errorf("CA status = %q, want %q", ca.Status, models.CAStatusActive)
	}
	if ca.Fingerprint == "" {
		t.Error("CA fingerprint is empty")
	}
	if ca.OwnerOperatorID != op.ID {
		t.Errorf("CA owner = %q, want %q", ca.OwnerOperatorID, op.ID)
	}
}

// TestMintCAForOperator tests the core mint-flow extraction.
func TestMintCAForOperator_Success(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	ctx := context.Background()

	op := &models.Operator{
		ID:           "op-dave",
		Username:     "dave",
		PasswordHash: "x",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}

	// Mint a CA directly via the helper.
	ca, err := w.mintCAForOperator(ctx, op, "dave-test-ca", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("mintCAForOperator = %v, want nil", err)
	}

	if ca == nil {
		t.Fatal("returned CA is nil")
		return
	}
	if ca.Name != "dave-test-ca" {
		t.Errorf("CA name = %q, want dave-test-ca", ca.Name)
	}
	if ca.Status != models.CAStatusActive {
		t.Errorf("CA status = %q, want %q", ca.Status, models.CAStatusActive)
	}
	if ca.Fingerprint == "" {
		t.Error("CA fingerprint is empty")
	}

	// Verify it's persisted in store.
	retrieved, err := s.GetCA(ctx, ca.ID)
	if err != nil {
		t.Fatal(err)
	}
	if retrieved.Name != ca.Name {
		t.Errorf("retrieved CA name = %q, want %q", retrieved.Name, ca.Name)
	}
}

func TestMintCAForOperator_ErrorWhenMasterNil(t *testing.T) {
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	w, err := New(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// No master set.

	ctx := context.Background()
	op := &models.Operator{
		ID:           "op-eve",
		Username:     "eve",
		PasswordHash: "x",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}

	// mintCAForOperator should return ErrCAMasterNotConfigured.
	_, err = w.mintCAForOperator(ctx, op, "eve-ca", 365*24*time.Hour)
	if err == nil {
		t.Fatal("mintCAForOperator with nil master: got nil error, want ErrCAMasterNotConfigured")
		return
	}
	if !strings.Contains(err.Error(), "ca master key not configured") {
		t.Errorf("error message = %q, want to contain 'ca master key not configured'", err.Error())
	}
}

// TestHandleCACreate_StillWorks verifies rефакторинг doesn't break existing handler.
func TestHandleCACreate_StillWorks(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	cookie := mintSession(t, s, "frank", "user")

	form := "name=frank-ca&duration=8760h"
	req := httptest.NewRequest(http.MethodPost, "/ui/cas", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("handleCACreate: status = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}

	// Verify CA was created and appears in redirect.
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "/ui/cas/") {
		t.Errorf("redirect location = %q, want /ui/cas/<id>", location)
	}

	// Verify audit entry.
	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if entry.Action == "ca.created" && entry.Details == "frank-ca" {
			found = true
			break
		}
	}
	if !found {
		t.Error("audit entry for ca.created not found")
	}
}
