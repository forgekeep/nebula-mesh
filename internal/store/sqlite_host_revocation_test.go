package store

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func addHostCertificateHistory(t *testing.T, s *SQLiteStore, hostID, prefix string) []string {
	t.Helper()

	ctx := t.Context()
	now := time.Now()
	fingerprints := make([]string, 0, 3)
	var current string
	for index := range 3 {
		fingerprint := fmt.Sprintf("%s-%d", prefix, index+1)
		err := s.SaveCertificateAndUpdateHostCert(
			ctx,
			hostID,
			current,
			[]byte("test certificate "+fingerprint),
			fingerprint,
			now.Add(-time.Hour),
			now.Add(time.Hour),
		)
		if err != nil {
			t.Fatalf("save certificate %s: %v", fingerprint, err)
		}
		fingerprints = append(fingerprints, fingerprint)
		current = fingerprint
	}
	return fingerprints
}

func requireFingerprintsPresent(t *testing.T, got, want []string) {
	t.Helper()
	for _, fingerprint := range want {
		if !slices.Contains(got, fingerprint) {
			t.Errorf("blocklist %v does not contain certificate fingerprint %q", got, fingerprint)
		}
	}
}

func requireFingerprintsAbsent(t *testing.T, got, unwanted []string) {
	t.Helper()
	for _, fingerprint := range unwanted {
		if slices.Contains(got, fingerprint) {
			t.Errorf("blocklist %v unexpectedly contains certificate fingerprint %q", got, fingerprint)
		}
	}
}

func TestBlockHostAndAddToBlocklist_SEC_PERSIST_001RevokesCertificateHistory(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	fingerprints := addHostCertificateHistory(t, fixture.store, fixture.host.ID, "blocked-cert")
	now := time.Now()
	const expired = "expired-cert"
	mustExec(t, fixture.store.db, `
		INSERT INTO certificates (id, host_id, fingerprint, pem, not_before, not_after, is_current, ca_id)
		VALUES (?, ?, ?, 'expired certificate', ?, ?, 0, ?)`,
		expired, fixture.host.ID, expired, now.Add(-2*time.Hour), now.Add(-time.Hour), fixture.host.CAID)

	if _, err := fixture.store.BlockHostAndAddToBlocklist(t.Context(), fixture.host.ID, "test"); err != nil {
		t.Fatal(err)
	}

	blocklist, err := fixture.store.GetBlocklistForCA(t.Context(), fixture.host.CAID)
	if err != nil {
		t.Fatal(err)
	}
	requireFingerprintsPresent(t, blocklist, fingerprints)
	requireFingerprintsAbsent(t, blocklist, []string{expired})
	otherCAList, err := fixture.store.GetBlocklistForCA(t.Context(), fixture.other.CAID)
	if err != nil {
		t.Fatal(err)
	}
	requireFingerprintsAbsent(t, otherCAList, fingerprints)
	fixture.requireDeltas(t, fixture.versions, 1, 1, 0)
}

func TestDeleteHostAndBlockCert_SEC_PERSIST_001RevokesCertificateHistory(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	fingerprints := addHostCertificateHistory(t, fixture.store, fixture.host.ID, "deleted-cert")

	if err := fixture.store.DeleteHostAndBlockCert(t.Context(), fixture.host.ID, "test"); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.store.GetHost(t.Context(), fixture.host.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetHost error = %v, want ErrNotFound", err)
	}
	blocklist, err := fixture.store.GetBlocklistForCA(t.Context(), fixture.primary.CAID)
	if err != nil {
		t.Fatal(err)
	}
	requireFingerprintsPresent(t, blocklist, fingerprints)
	otherCAList, err := fixture.store.GetBlocklistForCA(t.Context(), fixture.other.CAID)
	if err != nil {
		t.Fatal(err)
	}
	requireFingerprintsAbsent(t, otherCAList, fingerprints)
	fixture.requireDeltas(t, fixture.versions, 1, 1, 0)
}

func TestBlockHost_SEC_PERSIST_001PublishesRevocationToIssuerCA(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	fingerprints := addHostCertificateHistory(t, fixture.store, fixture.host.ID, "issuer-cert")
	mustExec(t, fixture.store.db, `INSERT INTO blocklist (fingerprint, ca_id) VALUES (?, ?)`, fingerprints[0], fixture.other.CAID)

	if _, err := fixture.store.BlockHostAndAddToBlocklist(t.Context(), fixture.host.ID, "test"); err != nil {
		t.Fatal(err)
	}
	blocklist, err := fixture.store.GetBlocklistForCA(t.Context(), fixture.host.CAID)
	if err != nil {
		t.Fatal(err)
	}
	requireFingerprintsPresent(t, blocklist, fingerprints)
	otherCAList, err := fixture.store.GetBlocklistForCA(t.Context(), fixture.other.CAID)
	if err != nil {
		t.Fatal(err)
	}
	requireFingerprintsAbsent(t, otherCAList, fingerprints)
	fixture.requireDeltas(t, fixture.versions, 1, 1, 1)
}

func TestMigrate032_SEC_PERSIST_001BackfillsBlockedCertificateHistory(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	blockedHistory := addHostCertificateHistory(t, fixture.store, fixture.host.ID, "legacy-blocked")
	if err := fixture.store.AddToBlocklist(t.Context(), blockedHistory[len(blockedHistory)-1], fixture.host.ID, "legacy block"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.UpdateHostStatus(t.Context(), fixture.host.ID, models.HostStatusBlocked); err != nil {
		t.Fatal(err)
	}

	active := &models.Host{
		ID: "active-host", NetworkID: fixture.primary.ID, CAID: fixture.primary.CAID,
		Name: "active-host", NebulaIPs: []string{"10.42.0.11"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := fixture.store.CreateHost(t.Context(), active); err != nil {
		t.Fatal(err)
	}
	activeHistory := addHostCertificateHistory(t, fixture.store, active.ID, "active")

	foreignHost := &models.Host{
		ID: "foreign-host", NetworkID: fixture.other.ID, CAID: fixture.other.CAID,
		Name: "foreign-host", NebulaIPs: []string{"10.44.0.11"}, Groups: []string{},
		Role: models.HostRoleHost, Status: models.HostStatusEnrolled,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := fixture.store.CreateHost(t.Context(), foreignHost); err != nil {
		t.Fatal(err)
	}
	foreignHistory := addHostCertificateHistory(t, fixture.store, foreignHost.ID, "foreign-blocked")
	if err := fixture.store.AddToBlocklist(t.Context(), foreignHistory[len(foreignHistory)-1], foreignHost.ID, "legacy foreign block"); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.UpdateHostStatus(t.Context(), foreignHost.ID, models.HostStatusBlocked); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.store.db.ExecContext(t.Context(), `DELETE FROM schema_migrations WHERE name = ?`, hostCertificateRevocationMigration); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.Migrate(t.Context()); err != nil {
		t.Fatalf("apply migration 032: %v", err)
	}
	fixture.requireDeltas(t, fixture.versions, 1, 1, 1)
	if err := fixture.store.Migrate(t.Context()); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	fixture.requireDeltas(t, fixture.versions, 1, 1, 1)

	ownBlocklist, err := fixture.store.GetBlocklistForCA(t.Context(), fixture.primary.CAID)
	if err != nil {
		t.Fatal(err)
	}
	requireFingerprintsPresent(t, ownBlocklist, blockedHistory)
	requireFingerprintsAbsent(t, ownBlocklist, activeHistory)
	foreignBlocklist, err := fixture.store.GetBlocklistForCA(t.Context(), fixture.other.CAID)
	if err != nil {
		t.Fatal(err)
	}
	requireFingerprintsPresent(t, foreignBlocklist, foreignHistory)
	requireFingerprintsAbsent(t, foreignBlocklist, blockedHistory)
}

func TestHostCertificate_SEC_PERSIST_001RejectsLateWritesAfterBlock(t *testing.T) {
	fixture := newCAScopedVersionFixture(t)
	s, host, ctx := fixture.store, fixture.host, t.Context()
	now := time.Now()
	fingerprints := addHostCertificateHistory(t, s, host.ID, "late-write")
	current := fingerprints[len(fingerprints)-1]
	if _, err := s.BlockHostAndAddToBlocklist(ctx, host.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCertificateAndUpdateHostCert(ctx, host.ID, current, []byte("replacement"), "renewed", now, now.Add(time.Hour)); !errors.Is(err, ErrIssuanceNotAllowed) {
		t.Fatalf("renewal after block error = %v, want ErrIssuanceNotAllowed", err)
	}
	if err := s.SaveCertificateAndEnrollHost(ctx, host.ID, []byte("replacement"), "enrolled", now, now.Add(time.Hour)); !errors.Is(err, ErrIssuanceNotAllowed) {
		t.Fatalf("enrollment after block error = %v, want ErrIssuanceNotAllowed", err)
	}
	stored, err := s.GetHost(ctx, host.ID)
	if err != nil || stored.Status != models.HostStatusBlocked || stored.CertFingerprint != current {
		t.Fatalf("host after late writes = %#v, %v; want blocked with original fingerprint", stored, err)
	}
	if _, err := s.UnblockHost(ctx, host.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCertificateAndUpdateHostCert(ctx, host.ID, current, []byte("replacement"), "renewed", now, now.Add(time.Hour)); !errors.Is(err, ErrIssuanceNotAllowed) {
		t.Fatalf("renewal after unblock error = %v, want ErrIssuanceNotAllowed", err)
	}
}
