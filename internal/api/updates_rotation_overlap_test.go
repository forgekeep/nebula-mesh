package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/store"
)

// TestPoll_AcceptsPrevFingerprintDuringOverlap simulates auto-renew: the
// host row now has prev_cert_fingerprint pointing at the agent's on-disk
// cert. The server must accept the old fingerprint until either (a) the
// agent comes back with the new one or (b) the overlap window expires.
func TestPoll_AcceptsPrevFingerprintDuringOverlap(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	// Park the agent's actual fingerprint as the *previous* one and rotate
	// to a synthetic "new-fp" value. The agent has not yet observed the
	// rotation, so its next poll still uses the old fp.
	if err := st.SetPrevFingerprint(context.Background(), hostByFingerprint(t, st, agent.fingerprint).ID, agent.fingerprint, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE hosts SET cert_fingerprint = ? WHERE prev_cert_fingerprint = ?`, "new-fp-XYZ", agent.fingerprint); err != nil {
		t.Fatal(err)
	}

	// Agent still polls under the old fingerprint — must succeed.
	req := httptest.NewRequest("GET", "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("old-fp poll during overlap: status = %d, body = %s", w.Code, w.Body.String())
	}
}

// TestPoll_ClearsPrevFingerprintAfterAgentUpgrades — once the agent comes
// back with the new fingerprint, the previous slot is cleared so a leaked
// old cert cannot keep haunting the host row.
func TestPoll_ClearsPrevFingerprintAfterAgentUpgrades(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	ctx := context.Background()
	host := hostByFingerprint(t, st, agent.fingerprint)
	if err := st.SetPrevFingerprint(ctx, host.ID, "old-fp", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Poll under the *current* fingerprint with prev still populated.
	req := httptest.NewRequest("GET", "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("poll: status = %d, body = %s", w.Code, w.Body.String())
	}

	got, err := st.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrevCertFingerprint != "" {
		t.Errorf("PrevCertFingerprint = %q, want empty after current-fp poll", got.PrevCertFingerprint)
	}
	if got.CertRotatedAt != nil {
		t.Errorf("CertRotatedAt = %v, want nil after current-fp poll", got.CertRotatedAt)
	}
}

// TestPoll_RejectsStalePrevFingerprintAfterTimeout — once 2×poll_interval
// elapses without the agent upgrading, the slot is cleared and the old
// fingerprint is no longer accepted.
func TestPoll_RejectsStalePrevFingerprintAfterTimeout(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	ctx := context.Background()
	host := hostByFingerprint(t, st, agent.fingerprint)
	// Park the agent's fingerprint as previous, rotate to a different
	// current, and backdate the rotation past the overlap window.
	rotatedAt := time.Now().Add(-1 * time.Hour)
	if err := st.SetPrevFingerprint(ctx, host.ID, agent.fingerprint, rotatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().Exec(`UPDATE hosts SET cert_fingerprint = ? WHERE id = ?`, "new-fp-XYZ", host.ID); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("GET", "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("stale prev-fp poll: status = %d, want 401, body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "unknown_fingerprint") {
		t.Errorf("body = %q, want unknown_fingerprint", w.Body.String())
	}

	got, err := st.GetHost(ctx, host.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PrevCertFingerprint != "" {
		t.Errorf("PrevCertFingerprint = %q, want empty after timeout-clear", got.PrevCertFingerprint)
	}
}

// hostByFingerprint is a small test convenience that resolves the host row
// (regardless of current vs previous fingerprint) through the store.
func hostByFingerprint(t *testing.T, st *store.SQLiteStore, fp string) *struct{ ID string } {
	t.Helper()
	h, err := st.GetHostByFingerprint(context.Background(), fp)
	if err != nil {
		t.Fatal(err)
	}
	return &struct{ ID string }{ID: h.ID}
}
