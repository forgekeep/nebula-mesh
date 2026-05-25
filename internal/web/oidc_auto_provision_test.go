package web

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestOIDCUpsert_AutoProvisionsForUserRole(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	ctx := context.Background()

	// Construct OIDC with provisioner callback wired from Web.
	o := &OIDC{
		store:  s,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg: config.OIDCConfig{
			DefaultRole: "user",
		},
		states: make(map[string]time.Time),
	}
	o.provisionCA = w.provisionDefaultCA

	// Upsert a new operator (first login).
	op, err := o.upsertOperator(ctx, "https://issuer.example.com", "subject-alice-1", "alice", "Alice Smith")
	if err != nil {
		t.Fatalf("upsertOperator failed: %v", err)
	}

	// Verify operator was created with user role.
	if op.Username != "alice" {
		t.Errorf("Username = %q, want alice", op.Username)
	}
	if op.Role != "user" {
		t.Errorf("Role = %q, want user", op.Role)
	}

	// Verify default CA was auto-provisioned.
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatalf("ListCAsByOwner failed: %v", err)
	}
	if len(cas) != 1 {
		t.Fatalf("ListCAsByOwner returned %d CAs, want 1", len(cas))
	}

	ca := cas[0]
	if ca.Name != "alice-default" {
		t.Errorf("CA name = %q, want alice-default", ca.Name)
	}
	if ca.Status != models.CAStatusActive {
		t.Errorf("CA status = %q, want %q", ca.Status, models.CAStatusActive)
	}
	if ca.OwnerOperatorID != op.ID {
		t.Errorf("CA owner = %q, want %q", ca.OwnerOperatorID, op.ID)
	}
}

func TestOIDCUpsert_AutoProvisionsForAdminRole(t *testing.T) {
	w, s := newOperatorsWebWithMaster(t)
	ctx := context.Background()

	o := &OIDC{
		store:  s,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg: config.OIDCConfig{
			DefaultRole: "admin",
		},
		states: make(map[string]time.Time),
	}
	o.provisionCA = w.provisionDefaultCA

	// Upsert a new admin operator.
	op, err := o.upsertOperator(ctx, "https://issuer.example.com", "subject-bob-1", "bob", "Bob Admin")
	if err != nil {
		t.Fatalf("upsertOperator failed: %v", err)
	}

	if op.Role != "admin" {
		t.Errorf("Role = %q, want admin", op.Role)
	}

	// Verify CA was auto-provisioned.
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatalf("ListCAsByOwner failed: %v", err)
	}
	if len(cas) != 1 {
		t.Fatalf("ListCAsByOwner returned %d CAs, want 1", len(cas))
	}

	ca := cas[0]
	if ca.Name != "bob-default" {
		t.Errorf("CA name = %q, want bob-default", ca.Name)
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

func TestOIDCUpsert_SkipsProvisionWhenProvisionerNil(t *testing.T) {
	_, s := newOperatorsWebWithMaster(t)
	ctx := context.Background()

	// Create OIDC WITHOUT provisioner callback (nil).
	o := &OIDC{
		store:  s,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg: config.OIDCConfig{
			DefaultRole: "user",
		},
		states: make(map[string]time.Time),
		// provisionCA remains nil
	}

	// Upsert should not fail even though provisioner is nil.
	op, err := o.upsertOperator(ctx, "https://issuer.example.com", "subject-charlie-1", "charlie", "Charlie")
	if err != nil {
		t.Fatalf("upsertOperator failed: %v", err)
	}

	if op.Username != "charlie" {
		t.Errorf("Username = %q, want charlie", op.Username)
	}

	// Verify NO CA was created (provisioner was nil).
	cas, err := s.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		t.Fatalf("ListCAsByOwner failed: %v", err)
	}
	if len(cas) != 0 {
		t.Fatalf("ListCAsByOwner returned %d CAs, want 0", len(cas))
	}
}
