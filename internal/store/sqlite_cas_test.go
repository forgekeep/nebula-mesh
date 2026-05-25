package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// seedCA creates an operator and an active CA owned by it. The encrypted-key
// blobs are dummy — these tests exercise DeleteCA's reference checks, not key
// material.
func seedCA(t *testing.T, s *SQLiteStore, caID string) {
	t.Helper()
	ctx := context.Background()
	op := &models.Operator{
		ID:           "op-" + caID,
		Username:     "user-" + caID,
		DisplayName:  "user-" + caID,
		PasswordHash: "x",
		Role:         "user",
		Status:       models.OperatorStatusActive,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	if err := s.CreateCA(ctx, &models.CA{
		ID:                   caID,
		Name:                 caID,
		OwnerOperatorID:      op.ID,
		Fingerprint:          "fp-" + caID,
		CertPEM:              "pem",
		Status:               models.CAStatusActive,
		NotBefore:            time.Now(),
		NotAfter:             time.Now().Add(time.Hour),
		EncryptedKeyDEK:      []byte{1},
		NonceDEK:             []byte{1},
		EncryptedKeyMaterial: []byte{1},
		NonceKey:             []byte{1},
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
}

func mustExecStore(t *testing.T, s *SQLiteStore, query string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

func TestDeleteCA_SucceedsWhenUnreferenced(t *testing.T) {
	s := newTestStore(t)
	seedCA(t, s, "ca-free")

	if err := s.DeleteCA(context.Background(), "ca-free"); err != nil {
		t.Fatalf("DeleteCA on unreferenced CA: %v", err)
	}
	if _, err := s.GetCA(context.Background(), "ca-free"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetCA after delete: err = %v, want ErrNotFound", err)
	}
}

// TestDeleteCA_IgnoresEmptyCAIDRows pins that pre-multi-CA rows (ca_id = "",
// the column default) never block a delete. A regression that matched the
// empty string would over-block legitimate CA deletions.
func TestDeleteCA_IgnoresEmptyCAIDRows(t *testing.T) {
	s := newTestStore(t)
	seedCA(t, s, "ca-empty")
	// A legacy row carrying the default empty ca_id.
	mustExecStore(t, s, `INSERT INTO blocklist (fingerprint, ca_id) VALUES (?, ?)`, "bl-legacy", "")

	if err := s.DeleteCA(context.Background(), "ca-empty"); err != nil {
		t.Fatalf("DeleteCA blocked by an empty-ca_id row: %v", err)
	}
}

// TestDeleteCA_ReportsAllBlockers pins that when more than one table references
// the CA, the refusal lists each of them (the strings.Join path).
func TestDeleteCA_ReportsAllBlockers(t *testing.T) {
	const caID = "ca-multi"
	s := newTestStore(t)
	seedCA(t, s, caID)
	if err := s.CreateNetwork(context.Background(), &models.Network{
		ID: "n1", Name: "n1", CIDRs: []string{"10.0.0.0/24"}, CAID: caID, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	mustExecStore(t, s, `INSERT INTO blocklist (fingerprint, ca_id) VALUES (?, ?)`, "bl-fp1", caID)

	err := s.DeleteCA(context.Background(), caID)
	if err == nil {
		t.Fatal("DeleteCA succeeded while network and blocklist referenced the CA")
	}
	for _, want := range []string{"network", "blocklist entry"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err.Error(), want)
		}
	}
	if _, gerr := s.GetCA(context.Background(), caID); gerr != nil {
		t.Errorf("CA missing after refused delete: %v", gerr)
	}
}

// TestDeleteCA_RefusesWhileReferenced pins that DeleteCA refuses to orphan a
// reference in ANY of the four ca_id-carrying tables. Before the fix only
// networks was checked, so deleting a CA still referenced by a host,
// certificate, or blocklist row silently orphaned that row. Each case isolates
// its table: the other tables either don't exist or point at a different CA.
func TestDeleteCA_RefusesWhileReferenced(t *testing.T) {
	const caID = "ca-ref"

	for _, tc := range []struct {
		name      string
		wantLabel string
		seedRef   func(t *testing.T, s *SQLiteStore)
	}{
		{
			name:      "network",
			wantLabel: "network",
			seedRef: func(t *testing.T, s *SQLiteStore) {
				if err := s.CreateNetwork(context.Background(), &models.Network{
					ID: "n1", Name: "n1", CIDRs: []string{"10.0.0.0/24"}, CAID: caID, CreatedAt: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "host",
			wantLabel: "host",
			seedRef: func(t *testing.T, s *SQLiteStore) {
				// Network points at a different CA so only the host references caID
				// — mirrors a host whose ca_id diverged from its network's.
				if err := s.CreateNetwork(context.Background(), &models.Network{
					ID: "n1", Name: "n1", CIDRs: []string{"10.0.0.0/24"}, CAID: "other-ca", CreatedAt: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
				if err := s.CreateHost(context.Background(), &models.Host{
					ID: "h1", NetworkID: "n1", CAID: caID, Name: "h1",
					NebulaIPs: []string{"10.0.0.10"}, Groups: []string{},
					Role: models.HostRoleHost, Status: models.HostStatusPending,
					CreatedAt: time.Now(), UpdatedAt: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "certificate",
			wantLabel: "certificate",
			seedRef: func(t *testing.T, s *SQLiteStore) {
				// Host/network point at a different CA; only the cert row references caID.
				if err := s.CreateNetwork(context.Background(), &models.Network{
					ID: "n1", Name: "n1", CIDRs: []string{"10.0.0.0/24"}, CAID: "other-ca", CreatedAt: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
				if err := s.CreateHost(context.Background(), &models.Host{
					ID: "h1", NetworkID: "n1", CAID: "other-ca", Name: "h1",
					NebulaIPs: []string{"10.0.0.10"}, Groups: []string{},
					Role: models.HostRoleHost, Status: models.HostStatusPending,
					CreatedAt: time.Now(), UpdatedAt: time.Now(),
				}); err != nil {
					t.Fatal(err)
				}
				mustExecStore(t, s,
					`INSERT INTO certificates (id, host_id, fingerprint, pem, not_before, not_after, ca_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
					"cert1", "h1", "fp-cert1", "pem", time.Now(), time.Now().Add(time.Hour), caID)
			},
		},
		{
			name:      "blocklist",
			wantLabel: "blocklist entry",
			seedRef: func(t *testing.T, s *SQLiteStore) {
				// host_id NULL — the realistic orphan: the host was deleted (ON
				// DELETE SET NULL) but the blocklist row keeps its ca_id.
				mustExecStore(t, s, `INSERT INTO blocklist (fingerprint, ca_id) VALUES (?, ?)`, "bl-fp1", caID)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			seedCA(t, s, caID)
			tc.seedRef(t, s)

			err := s.DeleteCA(context.Background(), caID)
			if err == nil {
				t.Fatalf("DeleteCA succeeded while a %s referenced the CA — orphan created", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantLabel) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.wantLabel)
			}
			// The CA must still exist — a refused delete must not have removed it.
			if _, gerr := s.GetCA(context.Background(), caID); gerr != nil {
				t.Errorf("CA missing after refused delete: %v", gerr)
			}
		})
	}
}
