package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// TestSignedPoll_AuditRowPerBranch drives each failure branch of
// handleAgentUpdates (internal/api/updates.go) that records an
// auditHostAuthFailed row, then reads back the audit row and validates
// it against assertValidAuditRow (the audit-row contract test from
// audit_validator_test.go). Pins the (reason code, resource shape)
// contract for the signed-poll audit trail — operators key off these
// strings when filtering the audit log, so a drift here is observable
// to anyone running detection rules. Every audit-failed branch is
// covered; the pre-lookup missing-headers branch intentionally does
// not audit (see TestSignedPoll_MissingHeadersNotAudited).
func TestSignedPoll_AuditRowPerBranch(t *testing.T) {
	cases := []struct {
		name         string
		setup        func(t *testing.T, srv *Server) (req *http.Request, wantStatus int)
		wantReason   string
		wantResource string // "" means: must be empty (early-stage branch)
	}{
		{
			name: "unknown_fingerprint",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				bogus := enrolledAgent{
					fingerprint: "deadbeefdeadbeef",
					signingPub:  agent.signingPub,
					signingPriv: agent.signingPriv,
				}
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, bogus)
				return req, http.StatusUnauthorized
			},
			wantReason:   authReasonUnknownFingerprint,
			wantResource: "",
		},
		{
			name: "bad_signature_empty_signing_pem",
			// Reaches updates.go:83 — decodeSigningPublicKeyPEM returns
			// ErrBadSigningPEM on empty input. Reachable in production
			// via legacy host rows that pre-date ADR 0004 enrollment
			// (the surrounding comment in updates.go calls this out),
			// not just synthetic corruption.
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				host, err := srv.store.GetHostByFingerprint(context.Background(), agent.fingerprint)
				if err != nil {
					t.Fatalf("get host by fingerprint: %v", err)
				}
				if err := srv.store.UpdateHostSigningPub(
					context.Background(), host.ID, ""); err != nil {
					t.Fatalf("clear signing pub: %v", err)
				}
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent)
				return req, http.StatusUnauthorized
			},
			wantReason:   authReasonBadSignature,
			wantResource: "<non-empty-host-id>",
		},
		{
			name: "bad_signature_wrong_key",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent, withPrivateKey(otherPriv))
				return req, http.StatusUnauthorized
			},
			wantReason: authReasonBadSignature,
			// Resource is host.ID for branches reached AFTER fingerprint
			// lookup. The exact ID is unknown until the fixture runs, so
			// we just assert non-empty below.
			wantResource: "<non-empty-host-id>",
		},
		{
			name: "bad_signature_non_base64",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent)
				// Overwrite the signature header with non-base64 garbage.
				req.Header.Set(corepop.HeaderSignature, "!!!not-base64!!!")
				return req, http.StatusUnauthorized
			},
			wantReason:   authReasonBadSignature,
			wantResource: "<non-empty-host-id>",
		},
		{
			name: "timestamp_unparseable",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent, withTimestamp("not-a-date"))
				return req, http.StatusUnauthorized
			},
			wantReason:   authReasonTimestampSkew,
			wantResource: "<non-empty-host-id>",
		},
		{
			name: "timestamp_skewed",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				past := time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent, withTimestamp(past))
				return req, http.StatusUnauthorized
			},
			wantReason:   authReasonTimestampSkew,
			wantResource: "<non-empty-host-id>",
		},
		{
			name: "replayed_nonce",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				// First poll lands successfully and records the nonce.
				first := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, first, agent, withNonce("fixed-nonce-1234"))
				w := httptest.NewRecorder()
				srv.ServeHTTP(w, first)
				if w.Code != http.StatusOK {
					t.Fatalf("seed poll: status = %d, body = %s", w.Code, w.Body.String())
				}
				// The replay attempt. NOTE: the seed poll also wrote a
				// last-seen update; no audit row is emitted for the
				// success path, so the only auditHostAuthFailed row is
				// from the replay.
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent, withNonce("fixed-nonce-1234"))
				return req, http.StatusUnauthorized
			},
			wantReason:   authReasonReplayedNonce,
			wantResource: "<non-empty-host-id>",
		},
		{
			name: "host_blocked",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				host, err := srv.store.GetHostByFingerprint(context.Background(), agent.fingerprint)
				if err != nil {
					t.Fatalf("get host by fingerprint: %v", err)
				}
				// Block via the store directly so the only audit row in
				// the table is the one written by the signed-poll
				// handler — the assertion below requires exactly one row.
				if _, err := srv.store.BlockHostAndAddToBlocklist(
					context.Background(), host.ID, "test"); err != nil {
					t.Fatalf("block host: %v", err)
				}
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent)
				return req, http.StatusForbidden
			},
			wantReason:   authReasonRevoked,
			wantResource: "<non-empty-host-id>",
		},
		{
			name: "host_gone_after_delete_and_blocklist",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				host, err := srv.store.GetHostByFingerprint(context.Background(), agent.fingerprint)
				if err != nil {
					t.Fatalf("get host by fingerprint: %v", err)
				}
				// DeleteHostAndBlockCert removes the row and adds the
				// fingerprint to the blocklist — the exact state that
				// triggers the 410 gone branch (updates.go:58).
				if err := srv.store.DeleteHostAndBlockCert(
					context.Background(), host.ID, "test delete"); err != nil {
					t.Fatalf("delete host: %v", err)
				}
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent)
				return req, http.StatusGone
			},
			wantReason:   authReasonGone,
			wantResource: "", // host row gone by the time audit is recorded
		},
		{
			name: "rotation_overlap_window_expired",
			setup: func(t *testing.T, srv *Server) (*http.Request, int) {
				agent := enrolledFixture(t, srv)
				host, err := srv.store.GetHostByFingerprint(context.Background(), agent.fingerprint)
				if err != nil {
					t.Fatalf("get host by fingerprint: %v", err)
				}
				// Park the agent's fingerprint as the *previous* one
				// and rotate the host's current fingerprint to a
				// synthetic value, backdating the rotation past the
				// 2-minute overlap window (updates.go:38 returns
				// 2*time.Minute). The next poll under the old
				// fingerprint triggers the timeout branch
				// (updates.go:154) → unknown_fingerprint audit.
				rotatedAt := time.Now().Add(-1 * time.Hour)
				if err := srv.store.SetPrevFingerprint(
					context.Background(), host.ID, agent.fingerprint, rotatedAt); err != nil {
					t.Fatalf("set prev fingerprint: %v", err)
				}
				if err := srv.store.UpdateHostCert(
					context.Background(), host.ID, "synthetic-new-fp",
					time.Now().Add(time.Hour)); err != nil {
					t.Fatalf("update host cert: %v", err)
				}
				req := httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil)
				signPoll(t, req, agent)
				return req, http.StatusUnauthorized
			},
			wantReason:   authReasonUnknownFingerprint,
			wantResource: "<non-empty-host-id>",
		},
	}

	t.Run("missing_headers_not_audited", func(t *testing.T) {
		// A poll missing the PoP headers needs no token, fingerprint, or
		// signature, so an unauthenticated sender could bloat the audit
		// table at line rate if this branch wrote a row per request
		// (L10, 2026-06-12 audit). It must answer 400 without auditing.
		srv, st := newTestServer(t)
		ctx := context.Background()

		before, err := st.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/agent/updates", nil))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		after, err := st.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(after) != len(before) {
			t.Errorf("missing-headers poll wrote %d audit rows, want 0 (unauthenticated flood vector)", len(after)-len(before))
		}
	})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, st := newTestServer(t)
			ctx := context.Background()

			req, wantStatus := c.setup(t, srv)

			// Snapshot AFTER setup but BEFORE the poll. newTestServer
			// seeds a CA (ca.created) and enrolledFixture posts hosts
			// (host.create) — both legitimate setup audit rows. The
			// contract under test is that the poll request itself
			// emits exactly one audit row, no more, no less.
			prereqRows, err := st.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
			if err != nil {
				t.Fatalf("list audit entries (prereq): %v", err)
			}

			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != wantStatus {
				t.Fatalf("status = %d, want %d, body = %s",
					w.Code, wantStatus, w.Body.String())
			}

			rows, err := st.ListAuditEntries(ctx, store.AuditFilter{Limit: 100})
			if err != nil {
				t.Fatalf("list audit entries (post): %v", err)
			}
			if delta := len(rows) - len(prereqRows); delta != 1 {
				for i, r := range rows {
					t.Logf("row %d: action=%q actor=%q resource=%q details=%q",
						i, r.Action, r.Actor, r.Resource, r.Details)
				}
				t.Fatalf("poll emitted %d audit rows, want 1", delta)
			}
			// rows is sorted timestamp DESC, so the row from this poll
			// is at index 0.
			row := rows[0]

			assertValidAuditRow(t, row)
			if row.Action != auditHostAuthFailed {
				t.Errorf("action = %q, want %q", row.Action, auditHostAuthFailed)
			}
			if row.Details != c.wantReason {
				t.Errorf("details = %q, want %q", row.Details, c.wantReason)
			}
			switch c.wantResource {
			case "":
				if row.Resource != "" {
					t.Errorf("resource = %q, want empty for early-stage branch", row.Resource)
				}
			case "<non-empty-host-id>":
				if row.Resource == "" {
					t.Errorf("resource is empty; want non-empty host ID")
				}
			default:
				if row.Resource != c.wantResource {
					t.Errorf("resource = %q, want %q", row.Resource, c.wantResource)
				}
			}
		})
	}
}
