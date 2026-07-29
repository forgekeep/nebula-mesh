package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/credentialhash"
	"github.com/forgekeep/nebula-mesh/internal/models"
)

func TestMeshImportLifecycleStoresOnlyTokenHash(t *testing.T) {
	s, session, now := newMeshImportFixture(t, nil)
	ctx := context.Background()

	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT token_hash FROM mesh_imports WHERE id = ?`, session.ID).Scan(&stored); err != nil {
		t.Fatalf("read token hash: %v", err)
	}
	if stored != session.TokenHash || stored == "raw-bootstrap-token" {
		t.Fatalf("stored token = %q, want supplied hash only", stored)
	}
	got, err := s.GetMeshImportByToken(ctx, "raw-bootstrap-token", now)
	if err != nil {
		t.Fatalf("get active import by token: %v", err)
	}
	if got.CAFingerprint != "ca-fingerprint" || got.CapturedNetworkConfigVersion != 1 {
		t.Fatalf("captured scope = fingerprint %q version %d", got.CAFingerprint, got.CapturedNetworkConfigVersion)
	}
	if _, err := s.GetMeshImportByToken(ctx, "raw-bootstrap-token", session.TokenExpiresAt); !errors.Is(err, ErrMeshImportTokenExpired) {
		t.Fatalf("get at expiry: %v, want ErrMeshImportTokenExpired", err)
	}

	newToken := "rotated"
	newExpiry := now.Add(2 * time.Hour)
	if err := s.RotateMeshImportToken(ctx, session.ID, newToken, newExpiry, now); err != nil {
		t.Fatalf("rotate token: %v", err)
	}
	if _, err := s.GetMeshImportByToken(ctx, "raw-bootstrap-token", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old token after rotate: %v, want ErrNotFound", err)
	}
	if _, err := s.GetMeshImportByToken(ctx, newToken, now); err != nil {
		t.Fatalf("new token after rotate: %v", err)
	}

	if err := s.CancelMeshImport(ctx, session.ID, "operator canceled", now.Add(time.Minute)); err != nil {
		t.Fatalf("cancel import: %v", err)
	}
	canceled, err := s.GetMeshImport(ctx, session.ID)
	if err != nil {
		t.Fatalf("get canceled import: %v", err)
	}
	if canceled.Status != models.MeshImportStatusCanceled || canceled.CanceledAt == nil || canceled.TerminalReason != "operator canceled" {
		t.Fatalf("canceled session = %#v", canceled)
	}
	if err := s.RotateMeshImportToken(ctx, session.ID, "again", newExpiry, now); !errors.Is(err, ErrMeshImportNotCollecting) {
		t.Fatalf("rotate canceled session: %v, want ErrMeshImportNotCollecting", err)
	}
}

func TestCreateMeshImportChallengeLimitsFingerprintAndPrunesStaleRows(t *testing.T) {
	s, session, now := newMeshImportFixture(t, nil)
	ctx := context.Background()
	first := meshImportChallenge(session.ID, "challenge-first", "fp-shared", "signing", "payload", now)
	second := meshImportChallenge(session.ID, "challenge-second", "fp-shared", "signing", "payload", now)
	third := meshImportChallenge(session.ID, "challenge-third", "fp-shared", "signing", "payload", now)
	for _, challenge := range []*models.MeshImportChallenge{first, second} {
		if err := s.CreateMeshImportChallenge(ctx, challenge, now); err != nil {
			t.Fatalf("create %s: %v", challenge.ID, err)
		}
	}
	if err := s.CreateMeshImportChallenge(ctx, third, now); !errors.Is(err, ErrMeshImportChallengeLimit) {
		t.Fatalf("third active challenge error = %v, want ErrMeshImportChallengeLimit", err)
	}
	if count := meshImportChallengeCount(t, s, session.ID); count != 2 {
		t.Fatalf("challenge rows after limit = %d, want 2", count)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE mesh_import_challenges SET consumed_at = ? WHERE id = ?`, now, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE mesh_import_challenges SET expires_at = ? WHERE id = ?`, now, second.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateMeshImportChallenge(ctx, third, now); err != nil {
		t.Fatalf("create after stale cleanup: %v", err)
	}
	if count := meshImportChallengeCount(t, s, session.ID); count != 1 {
		t.Fatalf("challenge rows after cleanup = %d, want 1", count)
	}
	for _, id := range []string{first.ID, second.ID} {
		if _, err := s.GetMeshImportChallenge(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("get stale challenge %s: %v, want ErrNotFound", id, err)
		}
	}
}

func TestCreateMeshImportChallengeLimitsExpectedSessionCapacity(t *testing.T) {
	expected := 2
	s, session, now := newMeshImportFixture(t, &expected)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		challenge := meshImportChallenge(session.ID, fmt.Sprintf("challenge-%d", i), fmt.Sprintf("fp-%d", i), "signing", "payload", now)
		if err := s.CreateMeshImportChallenge(ctx, challenge, now); err != nil {
			t.Fatalf("create challenge %d: %v", i, err)
		}
	}
	extra := meshImportChallenge(session.ID, "challenge-extra", "fp-extra", "signing", "payload", now)
	if err := s.CreateMeshImportChallenge(ctx, extra, now); !errors.Is(err, ErrMeshImportChallengeLimit) {
		t.Fatalf("challenge above expected capacity error = %v, want ErrMeshImportChallengeLimit", err)
	}
	if count := meshImportActiveChallengeCount(t, s, session.ID, now); count != 4 {
		t.Fatalf("active challenges = %d, want 4", count)
	}
}

func TestCreateMeshImportChallengeEnforcesHardSessionCapacity(t *testing.T) {
	const hardLimit = 4096
	s, session, now := newMeshImportFixture(t, nil)
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < hardLimit; i++ {
		if _, err := tx.Exec(`INSERT INTO mesh_import_challenges (
			id, mesh_import_id, certificate_fingerprint, agent_signing_pub_pem,
			payload_hash, server_nonce, expires_at, created_at)
			VALUES (?, ?, ?, 'signing', 'payload', 'nonce', ?, ?)`,
			fmt.Sprintf("seed-%d", i), session.ID, fmt.Sprintf("seed-fp-%d", i), now.Add(time.Minute), now); err != nil {
			_ = tx.Rollback()
			t.Fatalf("seed challenge %d: %v", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	extra := meshImportChallenge(session.ID, "challenge-extra", "fp-extra", "signing", "payload", now)
	if err := s.CreateMeshImportChallenge(context.Background(), extra, now); !errors.Is(err, ErrMeshImportChallengeLimit) {
		t.Fatalf("challenge above hard capacity error = %v, want ErrMeshImportChallengeLimit", err)
	}
	if count := meshImportActiveChallengeCount(t, s, session.ID, now); count != hardLimit {
		t.Fatalf("active challenges = %d, want %d", count, hardLimit)
	}
}

func TestConcurrentMeshImportChallengesStopExactlyAtSessionCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "challenge-race.db")
	s, err := NewSQLiteStore(path, WithCredentialHasher(newTestCredentialHasher(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	expected := 2
	session, now := seedMeshImportFixture(t, s, &expected)

	const workers = 12
	start := make(chan struct{})
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			challenge := meshImportChallenge(session.ID, fmt.Sprintf("race-%d", i), fmt.Sprintf("race-fp-%d", i), "signing", "payload", now)
			results <- s.CreateMeshImportChallenge(context.Background(), challenge, now)
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)

	var successes, limited, unexpected int
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrMeshImportChallengeLimit):
			limited++
		default:
			unexpected++
			t.Errorf("unexpected concurrent create error: %v", err)
		}
	}
	if successes != 4 || limited != workers-4 || unexpected != 0 {
		t.Fatalf("successes=%d limited=%d unexpected=%d, want 4/%d/0", successes, limited, unexpected, workers-4)
	}
	if count := meshImportActiveChallengeCount(t, s, session.ID, now); count != 4 {
		t.Fatalf("active challenges = %d, want 4", count)
	}
}

func TestRotateMeshImportTokenDeletesChallengesAtomically(t *testing.T) {
	s, session, now := newMeshImportFixture(t, nil)
	ctx := context.Background()
	first := meshImportChallenge(session.ID, "rotate-first", "rotate-fp-1", "signing", "payload", now)
	second := meshImportChallenge(session.ID, "rotate-second", "rotate-fp-2", "signing", "payload", now)
	for _, challenge := range []*models.MeshImportChallenge{first, second} {
		if err := s.CreateMeshImportChallenge(ctx, challenge, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE mesh_import_challenges SET consumed_at = ? WHERE id = ?`, now, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateMeshImportToken(ctx, session.ID, "rotated-with-cleanup", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if count := meshImportChallengeCount(t, s, session.ID); count != 0 {
		t.Fatalf("challenges after token rotation = %d, want 0", count)
	}
}

func TestCreateMeshImportChallengeRejectsTokenVerifiedBeforeRotation(t *testing.T) {
	s, session, now := newMeshImportFixture(t, nil)
	ctx := context.Background()
	oldTokenChallenge := meshImportChallenge(session.ID, "late-old-token", "late-old-fp", "signing", "payload", now)

	if err := s.RotateMeshImportToken(ctx, session.ID, "replacement", now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateMeshImportChallenge(ctx, oldTokenChallenge, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("create with token verified before rotation: %v, want ErrNotFound", err)
	}
	if count := meshImportChallengeCount(t, s, session.ID); count != 0 {
		t.Fatalf("challenges after late old-token request = %d, want 0", count)
	}
}

func TestRotateMeshImportTokenRollsBackWhenChallengeCleanupFails(t *testing.T) {
	s, session, now := newMeshImportFixture(t, nil)
	ctx := context.Background()
	challenge := meshImportChallenge(session.ID, "rotate-rollback", "rotate-rollback-fp", "signing", "payload", now)
	if err := s.CreateMeshImportChallenge(ctx, challenge, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TRIGGER fail_mesh_import_challenge_delete
		BEFORE DELETE ON mesh_import_challenges BEGIN SELECT RAISE(ABORT, 'blocked delete'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.RotateMeshImportToken(ctx, session.ID, "must-roll-back", now.Add(time.Hour), now); err == nil {
		t.Fatal("token rotation unexpectedly succeeded")
	}
	if _, err := s.GetMeshImportByToken(ctx, "raw-bootstrap-token", now); err != nil {
		t.Fatalf("old token hash was not restored: %v", err)
	}
	if _, err := s.GetMeshImportByToken(ctx, "must-roll-back", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("new token hash survived rollback: %v", err)
	}
	if count := meshImportChallengeCount(t, s, session.ID); count != 1 {
		t.Fatalf("challenges after failed rotation = %d, want 1", count)
	}
}

func TestRegisterImportedHostChallengeAndIdempotency(t *testing.T) {
	expected := 1
	s, session, now := newMeshImportFixture(t, &expected)
	ctx := context.Background()

	challenge := meshImportChallenge(session.ID, "challenge-1", "fp-1", "signing-1", "payload-1", now)
	if err := s.CreateMeshImportChallenge(ctx, challenge, now); err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	storedChallenge, err := s.GetMeshImportChallenge(ctx, challenge.ID)
	if err != nil || storedChallenge.ServerNonce != challenge.ServerNonce {
		t.Fatalf("get challenge: %#v, %v", storedChallenge, err)
	}
	registration := meshImportRegistration(session, challenge, "host-1", "10.42.0.10")
	result, err := s.RegisterImportedHost(ctx, registration, now.Add(time.Second))
	if err != nil {
		t.Fatalf("register host: %v", err)
	}
	if !result.Created || result.Host.Status != models.HostStatusImporting {
		t.Fatalf("registration result = %#v", result)
	}
	got, err := s.GetMeshImport(ctx, session.ID)
	if err != nil {
		t.Fatalf("get import: %v", err)
	}
	if got.Revision != 1 {
		t.Fatalf("revision = %d, want 1", got.Revision)
	}
	profile, err := s.GetHostAgentProfile(ctx, "host-1")
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if !profile.ConfigAckV1 || profile.PendingConfigVersion != 7 {
		t.Fatalf("profile delivery state = %#v", profile)
	}
	certificatePEM, err := s.GetCurrentCertificate(ctx, "host-1")
	if err != nil || string(certificatePEM) != registration.Snapshot.CertificatePEM {
		t.Fatalf("current imported certificate = %q, %v", certificatePEM, err)
	}
	if _, err := s.RegisterImportedHost(ctx, registration, now.Add(2*time.Second)); !errors.Is(err, ErrMeshImportChallengeUsed) {
		t.Fatalf("reuse challenge: %v, want ErrMeshImportChallengeUsed", err)
	}

	retryChallenge := meshImportChallenge(session.ID, "challenge-2", "fp-1", "signing-1", "payload-1", now)
	if err := s.CreateMeshImportChallenge(ctx, retryChallenge, now); err != nil {
		t.Fatalf("create retry challenge: %v", err)
	}
	retry := meshImportRegistration(session, retryChallenge, "host-retry", "10.42.0.11")
	retryResult, err := s.RegisterImportedHost(ctx, retry, now.Add(time.Second))
	if err != nil {
		t.Fatalf("idempotent registration: %v", err)
	}
	if retryResult.Created || retryResult.Host.ID != "host-1" {
		t.Fatalf("idempotent result = %#v", retryResult)
	}
	got, _ = s.GetMeshImport(ctx, session.ID)
	if got.Revision != 1 {
		t.Fatalf("revision after idempotent retry = %d, want 1", got.Revision)
	}

	conflictChallenge := meshImportChallenge(session.ID, "challenge-3", "fp-1", "signing-other", "payload-1", now)
	if err := s.CreateMeshImportChallenge(ctx, conflictChallenge, now); err != nil {
		t.Fatalf("create conflict challenge: %v", err)
	}
	conflict := meshImportRegistration(session, conflictChallenge, "host-other", "10.42.0.12")
	if _, err := s.RegisterImportedHost(ctx, conflict, now.Add(time.Second)); !errors.Is(err, ErrMeshImportSigningKeyConflict) {
		t.Fatalf("different signing key: %v, want ErrMeshImportSigningKeyConflict", err)
	}

	secondChallenge := meshImportChallenge(session.ID, "challenge-4", "fp-2", "signing-2", "payload-2", now)
	if err := s.CreateMeshImportChallenge(ctx, secondChallenge, now); err != nil {
		t.Fatalf("create second-host challenge: %v", err)
	}
	second := meshImportRegistration(session, secondChallenge, "host-2", "10.42.0.20")
	if _, err := s.RegisterImportedHost(ctx, second, now.Add(time.Second)); !errors.Is(err, ErrMeshImportExpectedHostsReached) {
		t.Fatalf("registration above expected count: %v, want ErrMeshImportExpectedHostsReached", err)
	}
}

func TestRegisterImportedHostRejectsExpiredChallengeAndDuplicateIP(t *testing.T) {
	s, session, now := newMeshImportFixture(t, nil)
	ctx := context.Background()

	expired := meshImportChallenge(session.ID, "expired", "fp-expired", "signing-expired", "payload-expired", now)
	expired.ExpiresAt = now.Add(-time.Second)
	if err := s.CreateMeshImportChallenge(ctx, expired, now.Add(-time.Minute)); err != nil {
		t.Fatalf("create expired challenge: %v", err)
	}
	if _, err := s.RegisterImportedHost(ctx, meshImportRegistration(session, expired, "expired-host", "10.42.0.5"), now); !errors.Is(err, ErrMeshImportChallengeExpired) {
		t.Fatalf("expired challenge: %v, want ErrMeshImportChallengeExpired", err)
	}

	first := meshImportChallenge(session.ID, "first", "fp-first", "signing-first", "payload-first", now)
	if err := s.CreateMeshImportChallenge(ctx, first, now); err != nil {
		t.Fatalf("create first challenge: %v", err)
	}
	if _, err := s.RegisterImportedHost(ctx, meshImportRegistration(session, first, "first-host", "10.42.0.9"), now); err != nil {
		t.Fatalf("register first host: %v", err)
	}
	second := meshImportChallenge(session.ID, "second", "fp-second", "signing-second", "payload-second", now)
	if err := s.CreateMeshImportChallenge(ctx, second, now); err != nil {
		t.Fatalf("create second challenge: %v", err)
	}
	if _, err := s.RegisterImportedHost(ctx, meshImportRegistration(session, second, "second-host", "10.42.0.9"), now); !errors.Is(err, ErrIPTaken) {
		t.Fatalf("duplicate overlay IP: %v, want ErrIPTaken", err)
	}
}

func TestCancelMeshImportCreatesTombstoneAndAllowsReplacement(t *testing.T) {
	s, firstSession, now := newMeshImportFixture(t, nil)
	ctx := context.Background()
	challenge := meshImportChallenge(firstSession.ID, "first-challenge", "fp-1", "signing-1", "payload-1", now)
	if err := s.CreateMeshImportChallenge(ctx, challenge, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterImportedHost(ctx, meshImportRegistration(firstSession, challenge, "host-1", "10.42.0.10"), now); err != nil {
		t.Fatal(err)
	}
	if err := s.CancelMeshImport(ctx, firstSession.ID, "aborted", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if count := meshImportChallengeCount(t, s, firstSession.ID); count != 0 {
		t.Fatalf("challenges after cancel = %d, want 0", count)
	}
	if _, err := s.GetHost(ctx, "host-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("canceled importing host still exists: %v", err)
	}
	tombstone, err := s.GetMeshImportTombstone(ctx, "fp-1")
	if err != nil {
		t.Fatalf("get tombstone: %v", err)
	}
	if tombstone.FormerHostID != "host-1" || tombstone.AgentSigningPubPEM != "signing-1" || tombstone.TerminalReason != "aborted" {
		t.Fatalf("tombstone = %#v", tombstone)
	}

	secondSession := &models.MeshImport{
		ID: "import-2", NetworkID: firstSession.NetworkID, CAID: firstSession.CAID,
		OwnerOperatorID: firstSession.OwnerOperatorID, Status: models.MeshImportStatusCollecting,
		TokenHash: tokenHash("second-session"), TokenExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateMeshImport(ctx, secondSession, "second-session"); err != nil {
		t.Fatalf("create replacement session: %v", err)
	}
	wrongKeyChallenge := meshImportChallenge(secondSession.ID, "wrong-key", "fp-1", "signing-other", "payload-new", now)
	wrongKeyChallenge.TokenHash = secondSession.TokenHash
	if err := s.CreateMeshImportChallenge(ctx, wrongKeyChallenge, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterImportedHost(ctx, meshImportRegistration(secondSession, wrongKeyChallenge, "host-wrong", "10.42.0.10"), now); !errors.Is(err, ErrMeshImportSigningKeyConflict) {
		t.Fatalf("replace tombstone with different signing key: %v, want ErrMeshImportSigningKeyConflict", err)
	}
	replacementChallenge := meshImportChallenge(secondSession.ID, "replacement", "fp-1", "signing-1", "payload-new", now)
	replacementChallenge.TokenHash = secondSession.TokenHash
	if err := s.CreateMeshImportChallenge(ctx, replacementChallenge, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterImportedHost(ctx, meshImportRegistration(secondSession, replacementChallenge, "host-new", "10.42.0.10"), now); err != nil {
		t.Fatalf("register replacement: %v", err)
	}
	if _, err := s.GetMeshImportTombstone(ctx, "fp-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tombstone after replacement: %v, want ErrNotFound", err)
	}
}

func TestCollectingMeshImportFreezesOrdinaryMutations(t *testing.T) {
	s, session, now := newMeshImportFixture(t, nil)
	ctx := context.Background()
	host := importTestHost(session, "ordinary-host", "10.42.0.30")
	host.Status = models.HostStatusPending
	if err := s.CreateHost(ctx, host); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("CreateHost error = %v", err)
	}
	token := &models.EnrollmentToken{ID: "token-1", HostID: host.ID, TokenHash: tokenHash("enroll"), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := s.CreateHostAndToken(ctx, host, token, "enroll"); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("CreateHostAndToken error = %v", err)
	}
	network := &models.Network{ID: session.NetworkID, Name: "renamed", CIDRs: []string{"10.42.0.0/16"}, CAID: session.CAID, CreatedAt: now}
	if err := s.UpdateNetwork(ctx, network); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("UpdateNetwork error = %v", err)
	}
	if err := s.SetNetworkConfig(ctx, session.NetworkID, "firewall", "deny"); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("SetNetworkConfig error = %v", err)
	}
	if err := s.SetNetworkConfigAndBumpVersion(ctx, session.NetworkID, "firewall", "deny"); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("SetNetworkConfigAndBumpVersion error = %v", err)
	}
	if err := s.BumpNetworkConfigVersion(ctx, session.NetworkID); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("BumpNetworkConfigVersion error = %v", err)
	}
	if err := s.UpdateCAStatus(ctx, session.CAID, models.CAStatusRetired); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("UpdateCAStatus error = %v", err)
	}
	predecessor := session.CAID
	if err := s.CreateCA(ctx, meshImportCA("successor", "successor-fp", session.OwnerOperatorID, &predecessor, now)); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("CreateCA successor error = %v", err)
	}
	if err := s.CreateNetwork(ctx, &models.Network{ID: "other-network", Name: "other", CIDRs: []string{"10.43.0.0/16"}, CAID: session.CAID, CreatedAt: now}); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("CreateNetwork with session CA error = %v", err)
	}
	otherCA := meshImportCA("other-ca", "other-fingerprint", session.OwnerOperatorID, nil, now)
	if err := s.CreateCA(ctx, otherCA); err != nil {
		t.Fatalf("create unrelated CA: %v", err)
	}
	otherNetwork := &models.Network{ID: "other-network", Name: "other", CIDRs: []string{"10.43.0.0/16"}, CAID: otherCA.ID, CreatedAt: now}
	if err := s.CreateNetwork(ctx, otherNetwork); err != nil {
		t.Fatalf("create unrelated network: %v", err)
	}
	otherNetwork.CAID = session.CAID
	if err := s.UpdateNetwork(ctx, otherNetwork); !errors.Is(err, ErrMeshImportInProgress) {
		t.Errorf("UpdateNetwork attaching session CA error = %v", err)
	}
}

func TestOnlyOneCollectingMeshImportPerNetwork(t *testing.T) {
	s, first, now := newMeshImportFixture(t, nil)
	second := &models.MeshImport{
		ID: "import-other", NetworkID: first.NetworkID, CAID: first.CAID,
		OwnerOperatorID: first.OwnerOperatorID, Status: models.MeshImportStatusCollecting,
		TokenHash: tokenHash("other"), TokenExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateMeshImport(context.Background(), second, "other"); !errors.Is(err, ErrMeshImportInProgress) {
		t.Fatalf("second collecting session: %v, want ErrMeshImportInProgress", err)
	}
}

func TestMeshImportCreationAndOrdinaryHostCreationAreAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	s, err := NewSQLiteStore(path, WithCredentialHasher(newTestCredentialHasher(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	op, ca, network, now := seedMeshImportScope(t, s)
	session := &models.MeshImport{
		ID: "import-race", NetworkID: network.ID, CAID: ca.ID, OwnerOperatorID: op.ID,
		Status: models.MeshImportStatusCollecting, TokenHash: tokenHash("race"),
		TokenExpiresAt: now.Add(time.Hour), CreatedAt: now, UpdatedAt: now,
	}
	host := importTestHost(session, "ordinary-race", "10.42.0.50")
	host.Status = models.HostStatusPending

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- s.CreateMeshImport(context.Background(), session, "race")
	}()
	go func() {
		<-start
		results <- s.CreateHost(context.Background(), host)
	}()
	close(start)
	firstErr, secondErr := <-results, <-results
	successes := 0
	for _, err := range []error{firstErr, secondErr} {
		if err == nil {
			successes++
			continue
		}
		if !errors.Is(err, ErrMeshImportInProgress) && !errors.Is(err, ErrMeshImportScopeInvalid) {
			t.Errorf("unexpected race loser error: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful writes = %d, want exactly one; errors: %v / %v", successes, firstErr, secondErr)
	}
	var sessions, hosts int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM mesh_imports WHERE status = ?`, models.MeshImportStatusCollecting).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE network_id = ?`, network.ID).Scan(&hosts); err != nil {
		t.Fatal(err)
	}
	if sessions+hosts != 1 {
		t.Fatalf("collecting sessions=%d hosts=%d, want one committed side", sessions, hosts)
	}
}

func TestConcurrentMeshImportRegistrationIsSingleWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	s, err := NewSQLiteStore(path, WithCredentialHasher(newTestCredentialHasher(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	session, now := seedMeshImportFixture(t, s, nil)

	const workers = maxActiveMeshImportChallengesPerFingerprint
	for i := 0; i < workers; i++ {
		challenge := meshImportChallenge(session.ID, fmt.Sprintf("challenge-%d", i), "fp-shared", "signing-shared", "payload-shared", now)
		if err := s.CreateMeshImportChallenge(context.Background(), challenge, now); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			challenge := meshImportChallenge(session.ID, fmt.Sprintf("challenge-%d", i), "fp-shared", "signing-shared", "payload-shared", now)
			_, err := s.RegisterImportedHost(context.Background(), meshImportRegistration(session, challenge, fmt.Sprintf("host-%d", i), fmt.Sprintf("10.42.0.%d", i+10)), now)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("concurrent registration: %v", err)
		}
	}
	var hosts, snapshots int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE status = ?`, models.HostStatusImporting).Scan(&hosts); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM mesh_import_snapshots WHERE mesh_import_id = ?`, session.ID).Scan(&snapshots); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetMeshImport(context.Background(), session.ID)
	if hosts != 1 || snapshots != 1 || got.Revision != 1 {
		t.Fatalf("hosts=%d snapshots=%d revision=%d, want 1/1/1", hosts, snapshots, got.Revision)
	}
}

func TestFinalizeMeshImportAppliesProposalAtomically(t *testing.T) {
	expected := 2
	s, session, now := newMeshImportFixture(t, &expected)
	first := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
	second := registerMeshImportTestHost(t, s, session, "two", "10.42.0.11", now)
	first.Host.Name = "lighthouse"
	first.Host.Role = models.HostRoleLighthouse
	first.Host.IsLighthouse = true
	first.Host.PublicIP = "203.0.113.10"
	second.Host.Name = "relay"
	second.Host.Role = models.HostRoleRelay
	second.Host.IsRelay = true
	second.Host.PublicIP = "203.0.113.11"
	advancedFalse := false
	second.Host.Advanced = &models.HostAdvanced{Punchy: &advancedFalse, MTU: 1300}

	input := MeshImportFinalizeInput{
		ID: session.ID, Revision: 2, Hosts: []MeshImportFinalizeHost{first, second},
		FirewallJSON: `{"inbound":[{"port":"22","proto":"tcp","group":"ops"}],"outbound":[]}`,
		Blocklist:    []string{strings.Repeat("a", 64)}, Now: now.Add(time.Minute),
	}
	setMeshImportSnapshotBlocklist(t, s, session.ID, input.Blocklist)
	if err := s.FinalizeMeshImport(context.Background(), input); err != nil {
		t.Fatalf("finalize mesh import: %v", err)
	}
	finalized, err := s.GetMeshImport(context.Background(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finalized.Status != models.MeshImportStatusFinalized || finalized.FinalizedAt == nil || finalized.Revision != 3 {
		t.Fatalf("finalized session = %#v", finalized)
	}
	for _, expectedHost := range input.Hosts {
		host, err := s.GetHost(context.Background(), expectedHost.Host.ID)
		if err != nil {
			t.Fatal(err)
		}
		if host.Status != models.HostStatusEnrolled || host.Name != expectedHost.Host.Name || host.Role != expectedHost.Host.Role {
			t.Fatalf("finalized host = %#v", host)
		}
	}
	if version, err := s.GetNetworkConfigVersion(context.Background(), session.NetworkID); err != nil || version != 2 {
		t.Fatalf("network config version = %d, %v", version, err)
	}
	if firewall, err := s.GetNetworkConfig(context.Background(), session.NetworkID, "firewall"); err != nil || firewall != input.FirewallJSON {
		t.Fatalf("firewall = %q, %v", firewall, err)
	}
	if blocklist, err := s.GetBlocklistForCA(context.Background(), session.CAID); err != nil || len(blocklist) != 1 || blocklist[0] != input.Blocklist[0] {
		t.Fatalf("blocklist = %#v, %v", blocklist, err)
	}
	if count := meshImportChallengeCount(t, s, session.ID); count != 0 {
		t.Fatalf("challenges after finalize = %d, want 0", count)
	}
}

func TestFinalizeMeshImportPreservesRevokedHostState(t *testing.T) {
	expected := 2
	s, session, now := newMeshImportFixture(t, &expected)
	revoked := registerMeshImportTestHost(t, s, session, "revoked", "10.42.0.10", now)
	ordinary := registerMeshImportTestHost(t, s, session, "ordinary", "10.42.0.11", now)
	historical := tokenHash("historical-revocation")
	blocklist := []string{revoked.Host.CertFingerprint, historical}
	setMeshImportSnapshotBlocklist(t, s, session.ID, blocklist)
	revoked.Host.Status = models.HostStatusBlocked

	err := s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
		ID: session.ID, Revision: 2, Hosts: []MeshImportFinalizeHost{revoked, ordinary},
		FirewallJSON: `{"inbound":[],"outbound":[]}`, Blocklist: blocklist, Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("finalize mesh import: %v", err)
	}
	revokedHost, err := s.GetHost(context.Background(), revoked.Host.ID)
	if err != nil || revokedHost.Status != models.HostStatusBlocked {
		t.Fatalf("revoked host = %#v, %v", revokedHost, err)
	}
	ordinaryHost, err := s.GetHost(context.Background(), ordinary.Host.ID)
	if err != nil || ordinaryHost.Status != models.HostStatusEnrolled {
		t.Fatalf("ordinary host = %#v, %v", ordinaryHost, err)
	}
	rows, err := s.db.Query(`SELECT fingerprint, host_id FROM blocklist WHERE ca_id = ? ORDER BY fingerprint`, session.CAID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	links := make(map[string]sql.NullString)
	for rows.Next() {
		var fingerprint string
		var hostID sql.NullString
		if err := rows.Scan(&fingerprint, &hostID); err != nil {
			t.Fatal(err)
		}
		links[fingerprint] = hostID
	}
	if link := links[revoked.Host.CertFingerprint]; !link.Valid || link.String != revoked.Host.ID {
		t.Fatalf("revoked blocklist link = %#v", link)
	}
	if link := links[historical]; link.Valid {
		t.Fatalf("historical blocklist link = %#v, want NULL", link)
	}
}

func TestFinalizeMeshImportRejectsUntrustedRevocationInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *SQLiteStore, *models.MeshImport, *MeshImportFinalizeHost, string)
		input  func(MeshImportFinalizeHost, string) []string
	}{
		{
			name: "caller omits fingerprint",
			mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport, proposal *MeshImportFinalizeHost, fingerprint string) {
				setMeshImportSnapshotBlocklist(t, s, session.ID, []string{fingerprint})
				proposal.Host.Status = models.HostStatusBlocked
			},
		},
		{
			name:  "caller adds fingerprint",
			input: func(MeshImportFinalizeHost, string) []string { return []string{tokenHash("caller-only")} },
		},
		{
			name: "invalid persisted blocklist",
			mutate: func(t *testing.T, s *SQLiteStore, _ *models.MeshImport, proposal *MeshImportFinalizeHost, _ string) {
				setMeshImportSnapshotBlocklistForHost(t, s, proposal.Host.ID, []string{"not-a-fingerprint"})
			},
		},
		{
			name: "proposal fingerprint",
			mutate: func(_ *testing.T, _ *SQLiteStore, _ *models.MeshImport, proposal *MeshImportFinalizeHost, _ string) {
				proposal.Host.CertFingerprint = tokenHash("tampered-proposal")
			},
		},
		{
			name: "staged host fingerprint",
			mutate: func(t *testing.T, s *SQLiteStore, _ *models.MeshImport, proposal *MeshImportFinalizeHost, _ string) {
				if _, err := s.db.Exec(`UPDATE hosts SET cert_fingerprint = ? WHERE id = ?`, tokenHash("tampered-staged"), proposal.Host.ID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "proposal status",
			mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport, proposal *MeshImportFinalizeHost, fingerprint string) {
				setMeshImportSnapshotBlocklist(t, s, session.ID, []string{fingerprint})
				proposal.Host.Status = models.HostStatusImporting
			},
			input: func(_ MeshImportFinalizeHost, fingerprint string) []string { return []string{fingerprint} },
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := 1
			s, session, now := newMeshImportFixture(t, &expected)
			proposal := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
			fingerprint := proposal.Host.CertFingerprint
			if test.mutate != nil {
				test.mutate(t, s, session, &proposal, fingerprint)
			}
			var blocklist []string
			if test.input != nil {
				blocklist = test.input(proposal, fingerprint)
			}
			err := s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
				ID: session.ID, Revision: 1, Hosts: []MeshImportFinalizeHost{proposal},
				FirewallJSON: `{"inbound":[],"outbound":[]}`, Blocklist: blocklist, Now: now.Add(time.Minute),
			})
			if !errors.Is(err, ErrMeshImportConflict) {
				t.Fatalf("finalize error = %v, want ErrMeshImportConflict", err)
			}
			stored, getErr := s.GetMeshImport(context.Background(), session.ID)
			if getErr != nil || stored.Status != models.MeshImportStatusCollecting {
				t.Fatalf("session after conflict = %#v, %v", stored, getErr)
			}
			if blocklist, getErr := s.GetBlocklistForCA(context.Background(), session.CAID); getErr != nil || len(blocklist) != 0 {
				t.Fatalf("blocklist after conflict = %#v, %v", blocklist, getErr)
			}
		})
	}
}

func TestFinalizeMeshImportRejectsDivergentPersistedBlocklists(t *testing.T) {
	expected := 2
	s, session, now := newMeshImportFixture(t, &expected)
	first := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
	second := registerMeshImportTestHost(t, s, session, "two", "10.42.0.11", now)
	setMeshImportSnapshotBlocklistForHost(t, s, first.Host.ID, []string{first.Host.CertFingerprint})
	first.Host.Status = models.HostStatusBlocked

	err := s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
		ID: session.ID, Revision: 2, Hosts: []MeshImportFinalizeHost{first, second},
		FirewallJSON: `{"inbound":[],"outbound":[]}`, Now: now.Add(time.Minute),
	})
	if !errors.Is(err, ErrMeshImportConflict) {
		t.Fatalf("finalize error = %v, want ErrMeshImportConflict", err)
	}
	if blocklist, getErr := s.GetBlocklistForCA(context.Background(), session.CAID); getErr != nil || len(blocklist) != 0 {
		t.Fatalf("blocklist after conflict = %#v, %v", blocklist, getErr)
	}
}

func TestFinalizeMeshImportRejectsStaleOrDriftedScopeWithoutPartialWrites(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *SQLiteStore, *models.MeshImport)
	}{
		{name: "network version", mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport) {
			if _, err := s.db.Exec(`UPDATE networks SET config_version = config_version + 1 WHERE id = ?`, session.NetworkID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "CA retired", mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport) {
			if _, err := s.db.Exec(`UPDATE cas SET status = ? WHERE id = ?`, models.CAStatusRetired, session.CAID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "CA fingerprint", mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport) {
			if _, err := s.db.Exec(`UPDATE cas SET fingerprint = 'changed' WHERE id = ?`, session.CAID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "preexisting blocklist", mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport) {
			if _, err := s.db.Exec(`INSERT INTO blocklist (fingerprint, reason, ca_id) VALUES (?, 'existing', ?)`, strings.Repeat("b", 64), session.CAID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "CA successor", mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport) {
			if _, err := s.db.Exec(`UPDATE cas SET predecessor_id = ? WHERE id = ?`, session.CAID, session.CAID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "newly attached network", mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport) {
			if _, err := s.db.Exec(`INSERT INTO networks (id, name, created_at, ca_id, config_version) VALUES ('attached', 'attached', ?, ?, 1)`, session.CreatedAt, session.CAID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unexpected host", mutate: func(t *testing.T, s *SQLiteStore, session *models.MeshImport) {
			if _, err := s.db.Exec(`INSERT INTO hosts (id, network_id, name, groups_json, role, status, created_at, updated_at, ca_id, kind) VALUES ('unexpected', ?, 'unexpected', '[]', 'host', 'pending', ?, ?, ?, 'agent')`, session.NetworkID, session.CreatedAt, session.CreatedAt, session.CAID); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expected := 1
			s, session, now := newMeshImportFixture(t, &expected)
			proposal := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
			test.mutate(t, s, session)
			err := s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
				ID: session.ID, Revision: 1, Hosts: []MeshImportFinalizeHost{proposal}, FirewallJSON: `{"inbound":[],"outbound":[]}`, Now: now.Add(time.Minute),
			})
			if !errors.Is(err, ErrMeshImportConflict) {
				t.Fatalf("finalize error = %v, want ErrMeshImportConflict", err)
			}
			host, err := s.GetHost(context.Background(), proposal.Host.ID)
			if err != nil || host.Status != models.HostStatusImporting {
				t.Fatalf("host changed after failed finalize: %#v, %v", host, err)
			}
			stored, _ := s.GetMeshImport(context.Background(), session.ID)
			if stored.Status != models.MeshImportStatusCollecting {
				t.Fatalf("session changed after failed finalize: %#v", stored)
			}
		})
	}
}

// SEC-PERSIST-001: a failed finalize must not expose any partial security state.
func TestFinalizeMeshImportRollsBackAllWrites(t *testing.T) {
	expected := 2
	s, session, now := newMeshImportFixture(t, &expected)
	first := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
	second := registerMeshImportTestHost(t, s, session, "two", "10.42.0.11", now)
	first.Host.Name = "duplicate"
	second.Host.Name = "duplicate"
	err := s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
		ID: session.ID, Revision: 2, Hosts: []MeshImportFinalizeHost{first, second},
		FirewallJSON: `{"inbound":[],"outbound":[]}`, Blocklist: []string{strings.Repeat("c", 64)}, Now: now,
	})
	if err == nil {
		t.Fatal("duplicate proposal unexpectedly finalized")
	}
	for _, proposal := range []MeshImportFinalizeHost{first, second} {
		host, getErr := s.GetHost(context.Background(), proposal.Host.ID)
		if getErr != nil || host.Status != models.HostStatusImporting || host.Name != proposal.Host.ID {
			t.Fatalf("host after rollback = %#v, %v", host, getErr)
		}
	}
	if _, err := s.GetNetworkConfig(context.Background(), session.NetworkID, "firewall"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("firewall survived rollback: %v", err)
	}
	if blocklist, err := s.GetBlocklistForCA(context.Background(), session.CAID); err != nil || len(blocklist) != 0 {
		t.Fatalf("blocklist after rollback = %#v, %v", blocklist, err)
	}
}

// SEC-PERSIST-001: proof cleanup and lifecycle state commit or roll back together.
func TestFinalizeMeshImportRollsBackChallengeCleanup(t *testing.T) {
	expected := 1
	s, session, now := newMeshImportFixture(t, &expected)
	proposal := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
	if count := meshImportChallengeCount(t, s, session.ID); count != 1 {
		t.Fatalf("challenge rows before finalize = %d, want 1", count)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_mesh_import_finalize
		BEFORE UPDATE OF status ON mesh_imports
		WHEN NEW.status = 'finalized' BEGIN SELECT RAISE(ABORT, 'blocked finalize'); END`); err != nil {
		t.Fatal(err)
	}
	err := s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
		ID: session.ID, Revision: 1, Hosts: []MeshImportFinalizeHost{proposal},
		FirewallJSON: `{"inbound":[],"outbound":[]}`, Now: now.Add(time.Minute),
	})
	if err == nil {
		t.Fatal("finalize unexpectedly succeeded")
	}
	if count := meshImportChallengeCount(t, s, session.ID); count != 1 {
		t.Fatalf("challenge rows after rollback = %d, want 1", count)
	}
	stored, getErr := s.GetMeshImport(context.Background(), session.ID)
	if getErr != nil || stored.Status != models.MeshImportStatusCollecting {
		t.Fatalf("session after rollback = %#v, %v", stored, getErr)
	}
	host, getErr := s.GetHost(context.Background(), proposal.Host.ID)
	if getErr != nil || host.Status != models.HostStatusImporting {
		t.Fatalf("host after rollback = %#v, %v", host, getErr)
	}
}

func TestFinalizeAndArrivingHostSerialize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "finalize-race.db")
	s, err := NewSQLiteStore(path, WithCredentialHasher(newTestCredentialHasher(t)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	session, now := seedMeshImportFixture(t, s, nil)
	proposal := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
	challenge := meshImportChallenge(session.ID, "challenge-arriving", "fp-arriving", "signing-arriving", "payload-arriving", now)
	if err := s.CreateMeshImportChallenge(context.Background(), challenge, now); err != nil {
		t.Fatal(err)
	}
	registration := meshImportRegistration(session, challenge, "host-arriving", "10.42.0.11")

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		results <- s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
			ID: session.ID, Revision: 1, Hosts: []MeshImportFinalizeHost{proposal},
			FirewallJSON: `{"inbound":[],"outbound":[]}`, Now: now.Add(time.Minute),
		})
	}()
	go func() {
		<-start
		_, registerErr := s.RegisterImportedHost(context.Background(), registration, now.Add(2*time.Second))
		results <- registerErr
	}()
	close(start)
	firstErr, secondErr := <-results, <-results
	successes := 0
	for _, result := range []error{firstErr, secondErr} {
		if result == nil {
			successes++
			continue
		}
		if !errors.Is(result, ErrMeshImportConflict) && !errors.Is(result, ErrMeshImportNotCollecting) {
			t.Fatalf("unexpected race result: %v", result)
		}
	}
	if successes != 1 {
		t.Fatalf("race successes = %d; errors = %v / %v", successes, firstErr, secondErr)
	}
	stored, err := s.GetMeshImport(context.Background(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	var importing, enrolled int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE network_id = ? AND status = ?`, session.NetworkID, models.HostStatusImporting).Scan(&importing); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM hosts WHERE network_id = ? AND status = ?`, session.NetworkID, models.HostStatusEnrolled).Scan(&enrolled); err != nil {
		t.Fatal(err)
	}
	if stored.Status == models.MeshImportStatusFinalized && (enrolled != 1 || importing != 0) {
		t.Fatalf("finalized race state enrolled=%d importing=%d", enrolled, importing)
	}
	if stored.Status == models.MeshImportStatusCollecting && (enrolled != 0 || importing != 2) {
		t.Fatalf("collecting race state enrolled=%d importing=%d", enrolled, importing)
	}
}

// SEC-PERSIST-001: finalize removes outstanding challenges atomically with
// the terminal session transition. A registration that loses that race must
// observe the terminal session, not misclassify the deleted challenge as an
// unknown proof.
func TestRegisterImportedHostAfterFinalizeReturnsNotCollecting(t *testing.T) {
	s, session, now := newMeshImportFixture(t, nil)
	ctx := context.Background()
	proposal := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
	challenge := meshImportChallenge(session.ID, "challenge-arriving", "fp-arriving", "signing-arriving", "payload-arriving", now)
	if err := s.CreateMeshImportChallenge(ctx, challenge, now); err != nil {
		t.Fatal(err)
	}
	registration := meshImportRegistration(session, challenge, "host-arriving", "10.42.0.11")
	if err := s.FinalizeMeshImport(ctx, MeshImportFinalizeInput{
		ID: session.ID, Revision: 1, Hosts: []MeshImportFinalizeHost{proposal},
		FirewallJSON: `{"inbound":[],"outbound":[]}`, Now: now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.RegisterImportedHost(ctx, registration, now.Add(2*time.Second)); !errors.Is(err, ErrMeshImportNotCollecting) {
		t.Fatalf("registration after finalize: %v, want ErrMeshImportNotCollecting", err)
	}
}

func TestFinalizeMeshImportRejectsStaleRevisionAndExpectedCount(t *testing.T) {
	expected := 2
	s, session, now := newMeshImportFixture(t, &expected)
	proposal := registerMeshImportTestHost(t, s, session, "one", "10.42.0.10", now)
	for _, revision := range []int64{0, 2} {
		err := s.FinalizeMeshImport(context.Background(), MeshImportFinalizeInput{
			ID: session.ID, Revision: revision, Hosts: []MeshImportFinalizeHost{proposal}, FirewallJSON: `{}`, Now: now,
		})
		if !errors.Is(err, ErrMeshImportConflict) {
			t.Fatalf("revision %d error = %v, want conflict", revision, err)
		}
	}
}

func registerMeshImportTestHost(t *testing.T, s *SQLiteStore, session *models.MeshImport, suffix, ip string, now time.Time) MeshImportFinalizeHost {
	t.Helper()
	challenge := meshImportChallenge(session.ID, "challenge-"+suffix, tokenHash("fp-"+suffix), "signing-"+suffix, "payload-"+suffix, now)
	if err := s.CreateMeshImportChallenge(context.Background(), challenge, now); err != nil {
		t.Fatal(err)
	}
	registration := meshImportRegistration(session, challenge, "host-"+suffix, ip)
	if _, err := s.RegisterImportedHost(context.Background(), registration, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	return MeshImportFinalizeHost{SnapshotID: registration.Snapshot.ID, Host: *registration.Host}
}

func newMeshImportFixture(t *testing.T, expected *int) (*SQLiteStore, *models.MeshImport, time.Time) {
	t.Helper()
	s := newTestStore(t)
	session, now := seedMeshImportFixture(t, s, expected)
	return s, session, now
}

func seedMeshImportFixture(t *testing.T, s *SQLiteStore, expected *int) (*models.MeshImport, time.Time) {
	t.Helper()
	op, ca, network, now := seedMeshImportScope(t, s)
	session := &models.MeshImport{
		ID: "import-1", NetworkID: network.ID, CAID: ca.ID, OwnerOperatorID: op.ID,
		Status: models.MeshImportStatusCollecting, ExpectedHosts: expected,
		TokenHash: tokenHash("raw-bootstrap-token"), TokenExpiresAt: now.Add(time.Hour),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := s.CreateMeshImport(context.Background(), session, "raw-bootstrap-token"); err != nil {
		t.Fatalf("create mesh import: %v", err)
	}
	return session, now
}

func seedMeshImportScope(t *testing.T, s *SQLiteStore) (*models.Operator, *models.CA, *models.Network, time.Time) {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC)
	op := &models.Operator{ID: "operator-1", Username: "operator", DisplayName: "Operator", PasswordHash: "hash", AuthProvider: models.OperatorAuthLocal, Status: models.OperatorStatusActive, Role: models.OperatorRoleAdmin, CreatedAt: now, UpdatedAt: now}
	if err := s.CreateOperator(ctx, op); err != nil {
		t.Fatalf("create operator: %v", err)
	}
	ca := meshImportCA("ca-1", "ca-fingerprint", op.ID, nil, now)
	if err := s.CreateCA(ctx, ca); err != nil {
		t.Fatalf("create CA: %v", err)
	}
	network := &models.Network{ID: "network-1", Name: "import-network", CIDRs: []string{"10.42.0.0/16"}, CAID: ca.ID, CreatedAt: now}
	if err := s.CreateNetwork(ctx, network); err != nil {
		t.Fatalf("create network: %v", err)
	}
	return op, ca, network, now
}

func meshImportCA(id, fingerprint, owner string, predecessor *string, now time.Time) *models.CA {
	return &models.CA{
		ID: id, Name: id, OwnerOperatorID: owner, CertPEM: "certificate", Fingerprint: fingerprint,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), Status: models.CAStatusActive,
		PredecessorID: predecessor, EncryptedKeyDEK: []byte("dek"), NonceDEK: []byte("nonce-dek"),
		EncryptedKeyMaterial: []byte("key"), NonceKey: []byte("nonce-key"), CreatedAt: now, UpdatedAt: now,
	}
}

func meshImportChallenge(sessionID, id, fingerprint, signingKey, payloadHash string, now time.Time) *models.MeshImportChallenge {
	hasher, err := credentialhash.New([]byte("store-test-master"))
	if err != nil {
		panic(err)
	}
	defer hasher.Destroy()
	tokenDigest, err := hasher.Digest(credentialhash.PurposeMeshImportToken, []byte("raw-bootstrap-token"))
	if err != nil {
		panic(err)
	}
	return &models.MeshImportChallenge{
		ID: id, MeshImportID: sessionID, TokenHash: tokenDigest, CertificateFingerprint: fingerprint,
		AgentSigningPubPEM: signingKey, PayloadHash: payloadHash, ServerNonce: "nonce-" + id,
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}
}

func meshImportRegistration(session *models.MeshImport, challenge *models.MeshImportChallenge, hostID, ip string) *models.MeshImportRegistration {
	now := challenge.CreatedAt
	host := importTestHost(session, hostID, ip)
	host.CertFingerprint = challenge.CertificateFingerprint
	host.SigningPubPEM = challenge.AgentSigningPubPEM
	host.CertExpiresAt = ptrTime(now.Add(24 * time.Hour))
	return &models.MeshImportRegistration{
		ChallengeID:          challenge.ID,
		CertificateNotBefore: now.Add(-time.Hour),
		CertificateNotAfter:  now.Add(24 * time.Hour),
		Host:                 host,
		Snapshot: &models.MeshImportSnapshot{
			ID: "snapshot-" + hostID, MeshImportID: session.ID, HostID: hostID,
			CertificateFingerprint: challenge.CertificateFingerprint, CertificatePEM: "cert-" + hostID,
			AgentSigningPubPEM: challenge.AgentSigningPubPEM, PayloadHash: challenge.PayloadHash,
			SnapshotJSON: `{"config":{"blocklist":[]}}`, CreatedAt: now, UpdatedAt: now,
		},
		Profile: &models.HostAgentProfile{
			HostID: hostID, MeshImportID: session.ID, NebulaConfigPath: "/etc/nebula/config.yml",
			NebulaCAPath: "/etc/nebula/ca.crt", NebulaCertPath: "/etc/nebula/host.crt", NebulaKeyPath: "/etc/nebula/host.key",
			ConfigAckV1: true, PendingConfigVersion: 7, CreatedAt: now, UpdatedAt: now,
		},
	}
}

func importTestHost(session *models.MeshImport, id, ip string) *models.Host {
	return &models.Host{
		ID: id, NetworkID: session.NetworkID, CAID: session.CAID, Name: id, NebulaIPs: []string{ip},
		Groups: []string{"imported"}, Role: models.HostRoleHost, ListenPort: 4242,
		Status: models.HostStatusImporting, Kind: models.HostKindAgent,
		CreatedAt: time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 7, 15, 10, 0, 0, 0, time.UTC),
	}
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func ptrTime(value time.Time) *time.Time { return &value }

func setMeshImportSnapshotBlocklist(t *testing.T, s *SQLiteStore, sessionID string, blocklist []string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"config": map[string]any{"blocklist": blocklist}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mesh_import_snapshots SET snapshot_json = ? WHERE mesh_import_id = ?`, string(payload), sessionID); err != nil {
		t.Fatal(err)
	}
}

func setMeshImportSnapshotBlocklistForHost(t *testing.T, s *SQLiteStore, hostID string, blocklist []string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"config": map[string]any{"blocklist": blocklist}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE mesh_import_snapshots SET snapshot_json = ? WHERE host_id = ?`, string(payload), hostID); err != nil {
		t.Fatal(err)
	}
}

func meshImportChallengeCount(t *testing.T, s *SQLiteStore, sessionID string) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM mesh_import_challenges WHERE mesh_import_id = ?`, sessionID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func meshImportActiveChallengeCount(t *testing.T, s *SQLiteStore, sessionID string, now time.Time) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM mesh_import_challenges
		WHERE mesh_import_id = ? AND consumed_at IS NULL AND expires_at > ?`, sessionID, now).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
