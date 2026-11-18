package store

import (
	"context"
	"errors"
	"slices"
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
		ctx, host, []byte("new-cert"), "new-fp", now, now.Add(time.Hour),
		func([]string) error {
			t.Error("render called for blocked host")
			return nil
		},
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
		ctx, host, []byte("new-cert"), "new-fp", now, now.Add(time.Hour),
		func([]string) error {
			t.Error("render called for disabled owner")
			return nil
		},
	)
	if !errors.Is(err, ErrIssuanceNotAllowed) {
		t.Fatalf("error = %v, want ErrIssuanceNotAllowed", err)
	}
	if _, err := s.GetCertificateInfo(ctx, host.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("certificate error = %v, want ErrNotFound", err)
	}
}

func TestMobileCertificate_SEC_PERSIST_001RenderFailureRollsBackRevocation(t *testing.T) {
	s, host, _ := mobileCertificateFixture(t)
	ctx := t.Context()
	now := time.Now()
	requireStoreTestNoError(t, s.SaveCertificateAndEnrollHost(ctx, host.ID, []byte("old-cert"), "old-fp", now, now.Add(time.Hour)))
	host, err := s.GetHost(ctx, host.ID)
	requireStoreTestNoError(t, err)
	version, err := s.GetNetworkConfigVersion(ctx, host.NetworkID)
	requireStoreTestNoError(t, err)
	renderErr := errors.New("render failed")

	err = s.SaveCertificateIfIssuanceAllowed(ctx, host,
		[]byte("new-cert"), "new-fp", now, now.Add(time.Hour), func(blocklist []string) error {
			if !slices.Equal(blocklist, []string{"old-fp"}) {
				t.Errorf("render blocklist = %v, want old-fp", blocklist)
			}
			return renderErr
		})
	if !errors.Is(err, renderErr) {
		t.Fatalf("error = %v, want %v", err, renderErr)
	}
	cert, err := s.GetCertificateInfo(ctx, host.ID)
	requireStoreTestNoError(t, err)
	if cert.Fingerprint != "old-fp" {
		t.Fatalf("current fingerprint = %q, want old-fp", cert.Fingerprint)
	}
	blocklist, err := s.GetBlocklistForCA(ctx, host.CAID)
	requireStoreTestNoError(t, err)
	if len(blocklist) != 0 {
		t.Fatalf("revocations persisted after render failure: %v", blocklist)
	}
	gotVersion, err := s.GetNetworkConfigVersion(ctx, host.NetworkID)
	requireStoreTestNoError(t, err)
	if gotVersion != version {
		t.Fatalf("version after render failure = %d, want %d", gotVersion, version)
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
