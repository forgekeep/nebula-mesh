package alerts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// recordingSink captures every alert it sees so tests can inspect them.
type recordingSink struct {
	mu     sync.Mutex
	events []Alert
	err    error
}

func (r *recordingSink) Notify(_ context.Context, a Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, a)
	return r.err
}

func (r *recordingSink) snapshot() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := make([]Alert, len(r.events))
	copy(cp, r.events)
	return cp
}

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s, err := store.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func seedNetwork(t *testing.T, s store.Store) string {
	t.Helper()
	n := &models.Network{
		ID:        "net_test",
		Name:      "test",
		CIDRs:     []string{"192.168.0.0/16"},
		CreatedAt: time.Now(),
	}
	if err := s.CreateNetwork(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	return n.ID
}

func seedEnrolledHost(t *testing.T, s store.Store, id, netID string, fp string, notBefore, notAfter time.Time) *models.Host {
	t.Helper()
	h := &models.Host{
		ID:        id,
		NetworkID: netID,
		Name:      id,
		NebulaIPs: []string{"192.168.1." + id},
		Groups:    []string{},
		Role:      models.HostRoleHost,
		Status:    models.HostStatusEnrolled,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := s.CreateHost(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCertificateAndEnrollHost(context.Background(), h.ID, []byte("dummy"), fp, notBefore, notAfter); err != nil {
		t.Fatal(err)
	}
	h.Status = models.HostStatusEnrolled
	h.CertFingerprint = fp
	return h
}

func TestScanner_NoExpiringCerts_NoAlerts(t *testing.T) {
	s := newTestStore(t)
	netID := seedNetwork(t, s)
	seedEnrolledHost(t, s, "h1", netID, "fp1", time.Now(), time.Now().Add(30*24*time.Hour))

	sink := &recordingSink{}
	sc := &Scanner{Store: s, Threshold: 24 * time.Hour, Sinks: []Sink{sink}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sink.snapshot(); len(got) != 0 {
		t.Errorf("expected no alerts, got %d: %+v", len(got), got)
	}
}

func TestScanner_ExpiringCert_EmitsOnce(t *testing.T) {
	s := newTestStore(t)
	netID := seedNetwork(t, s)
	expiry := time.Now().Add(2 * time.Hour)
	seedEnrolledHost(t, s, "h1", netID, "fp1", time.Now(), expiry)

	sink := &recordingSink{}
	sc := &Scanner{Store: s, Threshold: 24 * time.Hour, Sinks: []Sink{sink}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := sink.snapshot()
	if len(got) != 1 {
		t.Fatalf("first scan: got %d alerts, want 1: %+v", len(got), got)
	}
	if got[0].HostID != "h1" {
		t.Errorf("host_id = %q, want h1", got[0].HostID)
	}
	if got[0].SecondsUntilExpiry <= 0 || got[0].SecondsUntilExpiry > 3*60*60 {
		t.Errorf("seconds_until_expiry = %f, want ~7200s", got[0].SecondsUntilExpiry)
	}

	// Second scan with the same cert must not re-emit.
	if err := sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sink.snapshot(); len(got) != 1 {
		t.Errorf("second scan: got %d alerts, want 1 (dedup)", len(got))
	}
}

func TestScanner_CertRotated_AlertsAgain(t *testing.T) {
	s := newTestStore(t)
	netID := seedNetwork(t, s)
	expiry := time.Now().Add(2 * time.Hour)
	seedEnrolledHost(t, s, "h1", netID, "fp1", time.Now(), expiry)

	sink := &recordingSink{}
	sc := &Scanner{Store: s, Threshold: 24 * time.Hour, Sinks: []Sink{sink}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sink.snapshot(); len(got) != 1 {
		t.Fatalf("first scan: got %d, want 1", len(got))
	}

	// Rotate cert — but keep it inside the threshold so the scanner still cares.
	newExpiry := time.Now().Add(3 * time.Hour)
	if err := s.SaveCertificateAndUpdateHostCert(context.Background(), "h1", []byte("dummy2"), "fp2", time.Now(), newExpiry); err != nil {
		t.Fatal(err)
	}

	if err := sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sink.snapshot(); len(got) != 2 {
		t.Errorf("after rotation: got %d alerts, want 2 (re-alert on new not_after)", len(got))
	}
}

func TestScanner_BlockedHost_Excluded(t *testing.T) {
	s := newTestStore(t)
	netID := seedNetwork(t, s)
	expiry := time.Now().Add(2 * time.Hour)
	seedEnrolledHost(t, s, "h1", netID, "fp1", time.Now(), expiry)
	if _, err := s.BlockHostAndAddToBlocklist(context.Background(), "h1", "test"); err != nil {
		t.Fatal(err)
	}

	sink := &recordingSink{}
	sc := &Scanner{Store: s, Threshold: 24 * time.Hour, Sinks: []Sink{sink}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := sink.snapshot(); len(got) != 0 {
		t.Errorf("blocked host: got %d alerts, want 0", len(got))
	}
}

func TestScanner_SinkFailureDoesNotStopOthers(t *testing.T) {
	s := newTestStore(t)
	netID := seedNetwork(t, s)
	seedEnrolledHost(t, s, "h1", netID, "fp1", time.Now(), time.Now().Add(2*time.Hour))

	failing := &recordingSink{err: errors.New("boom")}
	good := &recordingSink{}
	sc := &Scanner{
		Store:     s,
		Threshold: 24 * time.Hour,
		Sinks:     []Sink{failing, good},
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(failing.snapshot()) != 1 {
		t.Errorf("failing sink should still see the event once")
	}
	if len(good.snapshot()) != 1 {
		t.Errorf("good sink should still see the event despite failing sink")
	}

	// And dedup should still kick in on a second scan: one sink failed,
	// but the alert was recorded as fired so we don't re-emit.
	if err := sc.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(good.snapshot()) != 1 {
		t.Errorf("second scan: good sink should still see exactly 1 alert, got %d", len(good.snapshot()))
	}
}
