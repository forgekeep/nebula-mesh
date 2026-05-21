package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/juev/nebula-mesh/internal/models"
)

func TestPoll_RespondsForbidden_WhenHostBlocked(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	ctx := context.Background()
	host, err := st.GetHostByFingerprint(ctx, agent.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.BlockHostAndAddToBlocklist(ctx, host.ID, "manual block"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403, body = %s", w.Code, w.Body.String())
	}
	var body revocationRevokedResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Reason != "revoked" {
		t.Errorf("reason = %q, want revoked", body.Reason)
	}
	if body.BlockedAt.IsZero() {
		t.Errorf("BlockedAt is zero")
	}
}

func TestPoll_RespondsGone_WhenHostDeletedButBlocklisted(t *testing.T) {
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	ctx := context.Background()
	host, err := st.GetHostByFingerprint(ctx, agent.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	// DeleteHostAndBlockCert removes the row and blocklists the
	// fingerprint — the exact state that should map to 410 gone.
	if err := st.DeleteHostAndBlockCert(ctx, host.ID, "manual delete"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410, body = %s", w.Code, w.Body.String())
	}
	var body revocationGoneResponse
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Reason != "gone" {
		t.Errorf("reason = %q, want gone", body.Reason)
	}
}

func TestPoll_UnknownStatusStillSucceeds(t *testing.T) {
	// Defensive: a non-blocked, non-deleted host must continue to receive
	// 200 even if its status string is something unexpected (forward-
	// compat with future status values that PR5 should not break).
	srv, st := newTestServer(t)
	agent := enrolledFixture(t, srv)

	ctx := context.Background()
	host, err := st.GetHostByFingerprint(ctx, agent.fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateHostStatus(ctx, host.ID, models.HostStatus("something-future")); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
	signPoll(t, req, agent)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 for unknown status, body = %s", w.Code, w.Body.String())
	}
}
