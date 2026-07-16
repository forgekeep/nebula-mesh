package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestSaveCertificateIfIssuanceAllowed_SEC_PERSIST_001RejectsBlockedHost(t *testing.T) {
	s, host, _ := mobileCertificateFixture(t)
	ctx := context.Background()
	requireStoreTestNoError(t, s.UpdateHostStatus(ctx, host.ID, models.HostStatusBlocked))

	now := time.Now()
	err := s.SaveCertificateIfIssuanceAllowed(
		ctx, host.ID, models.HostStatusPending, []byte("new-cert"), "new-fp", now, now.Add(time.Hour),
	)
	if !errors.Is(err, ErrIssuanceNotAllowed) {
		t.Fatalf("error = %v, want ErrIssuanceNotAllowed", err)
	}
	stored, err := s.GetHost(ctx, host.ID)
	requireStoreTestNoError(t, err)
	if stored.Status != models.HostStatusBlocked {
		t.Fatalf("status = %q, want blocked", stored.Status)
	}
	if _, err := s.GetCertificateInfo(ctx, host.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("certificate error = %v, want ErrNotFound", err)
	}
}

func TestSaveCertificateIfIssuanceAllowed_SEC_PERSIST_001RejectsDisabledOwner(t *testing.T) {
	s, host, owner := mobileCertificateFixture(t)
	ctx := context.Background()
	requireStoreTestNoError(t, s.DisableOperator(ctx, owner.ID))

	now := time.Now()
	err := s.SaveCertificateIfIssuanceAllowed(
		ctx, host.ID, models.HostStatusPending, []byte("new-cert"), "new-fp", now, now.Add(time.Hour),
	)
	if !errors.Is(err, ErrIssuanceNotAllowed) {
		t.Fatalf("error = %v, want ErrIssuanceNotAllowed", err)
	}
	if _, err := s.GetCertificateInfo(ctx, host.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("certificate error = %v, want ErrNotFound", err)
	}
}

func mobileCertificateFixture(t *testing.T) (*SQLiteStore, *models.Host, *models.Operator) {
	t.Helper()
	s := newTestStore(t)
	owner := createTestOperator(t, s)
	ca := createTestCA(t, s, "ca_mobile_certificate", "mobile-certificate", owner.ID, nil)
	network := &models.Network{
		ID: "net_mobile_certificate", Name: "mobile-certificate", CAID: ca.ID,
		CIDRs: []string{"10.80.0.0/16"}, CreatedAt: time.Now(),
	}
	requireStoreTestNoError(t, s.CreateNetwork(context.Background(), network))
	host := &models.Host{
		ID: "host_mobile_certificate", NetworkID: network.ID, CAID: ca.ID,
		Name: "mobile-certificate", NebulaIPs: []string{"10.80.0.10"},
		Role: models.HostRoleHost, Status: models.HostStatusPending,
		Kind: models.HostKindMobile, Variant: models.HostVariantAndroid,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	requireStoreTestNoError(t, s.CreateHost(context.Background(), host))
	return s, host, owner
}

func requireStoreTestNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
