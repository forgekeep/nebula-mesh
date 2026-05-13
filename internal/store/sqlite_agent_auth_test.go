package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
)

func newHostFixture(t *testing.T, s *SQLiteStore, id string) *models.Host {
	t.Helper()
	net := createTestNetwork(t, s)
	h := &models.Host{
		ID:        id,
		NetworkID: net.ID,
		Name:      "host-" + id,
		NebulaIP:  "192.168.100.10",
		Groups:    []string{"g"},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestSetPrevFingerprint_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "h1")

	rotatedAt := time.Now().UTC().Truncate(time.Second)
	if err := s.SetPrevFingerprint(ctx, h.ID, "old-fp", rotatedAt); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrevCertFingerprint != "old-fp" {
		t.Errorf("prev fingerprint = %q, want %q", got.PrevCertFingerprint, "old-fp")
	}
	if got.CertRotatedAt == nil || !got.CertRotatedAt.UTC().Equal(rotatedAt) {
		t.Errorf("cert_rotated_at = %v, want %v", got.CertRotatedAt, rotatedAt)
	}
}

func TestSetPrevFingerprint_NotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetPrevFingerprint(context.Background(), "missing", "fp", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestClearPrevFingerprint_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "h1")

	if err := s.SetPrevFingerprint(ctx, h.ID, "old-fp", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearPrevFingerprint(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrevCertFingerprint != "" {
		t.Errorf("prev fingerprint = %q, want empty", got.PrevCertFingerprint)
	}
	if got.CertRotatedAt != nil {
		t.Errorf("cert_rotated_at = %v, want nil", got.CertRotatedAt)
	}
}

func TestSetPendingRekey_CAS(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "h1")

	if err := s.SetPendingRekey(ctx, h.ID); err != nil {
		t.Fatalf("first SetPendingRekey: %v", err)
	}
	if err := s.SetPendingRekey(ctx, h.ID); !errors.Is(err, ErrRekeyAlreadyPending) {
		t.Fatalf("second SetPendingRekey err = %v, want ErrRekeyAlreadyPending", err)
	}
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.PendingRekey {
		t.Error("pending_rekey = false, want true")
	}
}

func TestSetPendingRekey_NotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetPendingRekey(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestClearPendingRekey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "h1")

	if err := s.SetPendingRekey(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClearPendingRekey(ctx, h.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PendingRekey {
		t.Error("pending_rekey = true after clear")
	}
}

func TestUpdateHostSigningPub(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "h1")

	pem := "-----BEGIN NEBULA ED25519 PUBLIC KEY-----\nbase64...\n-----END NEBULA ED25519 PUBLIC KEY-----\n"
	if err := s.UpdateHostSigningPub(ctx, h.ID, pem); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetHost(ctx, h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.SigningPubPEM != pem {
		t.Errorf("signing_pub_pem mismatch")
	}
}

func TestCreateTokenForHost_InvalidatesPrevious(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	h := newHostFixture(t, s, "h1")

	// Seed an initial token.
	first := &models.EnrollmentToken{
		ID: "tok_first", HostID: h.ID, Token: "old-token",
		ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now(),
	}
	if err := s.CreateToken(ctx, first); err != nil {
		t.Fatal(err)
	}
	// Regenerate; old token must be wiped.
	if err := s.CreateTokenForHost(ctx, h.ID, "new-token", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeToken(ctx, "old-token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old token err = %v, want ErrNotFound", err)
	}
	got, err := s.ConsumeToken(ctx, "new-token")
	if err != nil {
		t.Fatal(err)
	}
	if got.HostID != h.ID {
		t.Errorf("new token host_id = %q, want %q", got.HostID, h.ID)
	}
}
