package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// TestHandleOperatorDisable_NonExistent_Returns404 verifies that
// POST /ui/operators/{id}/disable with a non-existent {id} returns 404
// without writing an audit entry. Before this validation was added the
// handler 303'd to the bogus operator detail URL and wrote an
// `operator.disable` audit row with resource=<bogus id>, polluting the
// forensic record.
func TestHandleOperatorDisable_NonExistent_Returns404(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	req := httptest.NewRequest(http.MethodPost, "/ui/operators/op-does-not-exist/disable", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}

	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "operator.disable", Limit: 100})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	for _, e := range entries {
		if e.Resource == "op-does-not-exist" {
			t.Errorf("unexpected audit entry written for non-existent operator: %+v", e)
		}
	}
}

// TestHandleOperatorCreateAPIKey_NonExistent_Returns404 locks the
// NotFound 404 path against future regression. The handler previously
// swallowed all GetOperator errors as 404; the discrimination patch
// makes that explicit (NotFound → 404, internal error → 500 + log).
func TestHandleOperatorCreateAPIKey_NonExistent_Returns404(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	req := httptest.NewRequest(http.MethodPost, "/ui/operators/op-does-not-exist/api-keys", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestHandleOperatorEnable_NonExistent_Returns404 mirrors the Disable
// test for the Enable handler.
func TestHandleOperatorEnable_NonExistent_Returns404(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	req := httptest.NewRequest(http.MethodPost, "/ui/operators/op-does-not-exist/enable", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}

	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "operator.enable", Limit: 100})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	for _, e := range entries {
		if e.Resource == "op-does-not-exist" {
			t.Errorf("unexpected audit entry written for non-existent operator: %+v", e)
		}
	}
}

// TestHandleOperatorRevokeAPIKey_NonExistentOperator_Returns404 verifies
// that POST /ui/operators/{id}/api-keys/{kid}/revoke with a non-existent
// {id} returns 404 and does not revoke any API key (nor write an audit
// entry against the bogus id).
func TestHandleOperatorRevokeAPIKey_NonExistentOperator_Returns404(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	req := httptest.NewRequest(http.MethodPost,
		"/ui/operators/op-does-not-exist/api-keys/kid-anything/revoke", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}

	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "operator.api_key.revoke", Limit: 100})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	for _, e := range entries {
		if e.Resource == "op-does-not-exist" {
			t.Errorf("unexpected audit entry written for non-existent operator: %+v", e)
		}
	}
}

// TestHandleOperatorRevokeAPIKey_KidBelongsToDifferentOperator_Returns404
// verifies that POST /ui/operators/{A}/api-keys/{kid-of-B}/revoke returns
// 404, does NOT revoke the kid (the real owner's key stays active), and
// does NOT write an audit row mislabelling the action under A.
func TestHandleOperatorRevokeAPIKey_KidBelongsToDifferentOperator_Returns404(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	// Two non-admin operators, each owns a key. mintSession creates "root"
	// (admin); seed "alpha" and "beta" directly so we control which kid
	// belongs to which operator.
	for _, username := range []string{"alpha", "beta"} {
		if err := s.CreateOperator(context.Background(), &models.Operator{
			ID:           "op-" + username,
			Username:     username,
			PasswordHash: "x",
			Status:       models.OperatorStatusActive,
			Role:         "user",
			AuthProvider: models.OperatorAuthLocal,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}); err != nil {
			t.Fatalf("seed %s: %v", username, err)
		}
	}

	sum := sha256.Sum256([]byte("beta-raw-token"))
	betaKey := &models.OperatorAPIKey{
		ID:         "key-belongs-to-beta",
		OperatorID: "op-beta",
		Name:       "beta-ci",
		KeyHash:    hex.EncodeToString(sum[:]),
		CreatedAt:  time.Now(),
	}
	if err := s.CreateOperatorAPIKey(context.Background(), betaKey); err != nil {
		t.Fatalf("create beta key: %v", err)
	}

	// Admin attempts to revoke beta's key via alpha's URL namespace.
	req := httptest.NewRequest(http.MethodPost,
		"/ui/operators/op-alpha/api-keys/key-belongs-to-beta/revoke", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	// Body wording locks the side-channel: cross-operator-kid must look
	// identical to "kid genuinely missing" so an attacker can't distinguish
	// existence of someone else's key by probing.
	if body := strings.TrimSpace(rec.Body.String()); body != "api key not found" {
		t.Errorf("body = %q, want \"api key not found\" (distinct from \"operator not found\" would leak existence)", body)
	}

	// Verify beta's key was NOT revoked.
	got, err := s.GetOperatorAPIKey(context.Background(), "key-belongs-to-beta")
	if err != nil {
		t.Fatalf("get beta key: %v", err)
	}
	if got.RevokedAt != nil {
		t.Errorf("beta's key was unexpectedly revoked (revoked_at=%v)", got.RevokedAt)
	}

	// Verify no audit row was written under op-alpha (the URL operator).
	entries, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "operator.api_key.revoke", Limit: 100})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	for _, e := range entries {
		if e.Resource == "op-alpha" {
			t.Errorf("unexpected audit entry under op-alpha for cross-operator kid: %+v", e)
		}
	}
}

// TestHandleOperatorRevokeAPIKey_AlreadyRevoked_Idempotent verifies that
// revoking the same kid twice (or revoking a kid that DisableOperator
// already cascaded into the revoked state) returns 303 with no new audit
// row. The handler's early-return on key.RevokedAt != nil avoids a doomed
// store UPDATE; the audit log only records the original revoke event.
func TestHandleOperatorRevokeAPIKey_AlreadyRevoked_Idempotent(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	// Seed a user operator with one key, then admin revokes once.
	if err := s.CreateOperator(context.Background(), &models.Operator{
		ID:           "op-gamma",
		Username:     "gamma",
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("seed gamma: %v", err)
	}
	sum := sha256.Sum256([]byte("gamma-token"))
	if err := s.CreateOperatorAPIKey(context.Background(), &models.OperatorAPIKey{
		ID: "key-gamma", OperatorID: "op-gamma", Name: "g", KeyHash: hex.EncodeToString(sum[:]), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create gamma key: %v", err)
	}

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/ui/operators/op-gamma/api-keys/key-gamma/revoke", nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		return rec
	}

	// First revoke: 303, writes one audit row.
	if rec := post(); rec.Code != http.StatusSeeOther {
		t.Fatalf("first revoke: status = %d, want 303", rec.Code)
	}
	first, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "operator.api_key.revoke", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("after first revoke: %d audit entries, want 1", len(first))
	}

	// Second revoke (same kid, same operator, already revoked): 303, NO new audit row.
	if rec := post(); rec.Code != http.StatusSeeOther {
		t.Errorf("second revoke: status = %d, want 303 (idempotent)", rec.Code)
	}
	second, err := s.ListAuditEntries(context.Background(), store.AuditFilter{Action: "operator.api_key.revoke", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 {
		t.Errorf("after second revoke: %d audit entries, want 1 (no new row for idempotent re-revoke)", len(second))
	}
}

// TestHandleOperatorRevokeAPIKey_AfterDisableCascade_Idempotent verifies
// the early-return-on-revoked branch when the key was auto-revoked by a
// prior DisableOperator (not by an explicit prior revoke). This is the
// production-realistic flow: admin disables a compromised operator, then
// belt-and-suspenders POSTs an explicit key revoke. Must return 303 with
// no new audit row.
func TestHandleOperatorRevokeAPIKey_AfterDisableCascade_Idempotent(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")
	ctx := context.Background()

	if err := s.CreateOperator(ctx, &models.Operator{
		ID: "op-epsilon", Username: "epsilon", PasswordHash: "x",
		Status: models.OperatorStatusActive, Role: "user", AuthProvider: models.OperatorAuthLocal,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("seed epsilon: %v", err)
	}
	sum := sha256.Sum256([]byte("epsilon-token"))
	if err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: "key-epsilon", OperatorID: "op-epsilon", KeyHash: hex.EncodeToString(sum[:]), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	// Cascade-revoke via DisableOperator.
	if err := s.DisableOperator(ctx, "op-epsilon"); err != nil {
		t.Fatalf("disable: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/ui/operators/op-epsilon/api-keys/key-epsilon/revoke", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (idempotent after cascade revoke)", rec.Code)
	}
	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Action: "operator.api_key.revoke", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d revoke audit entries, want 0 (cascade doesn't audit each key; idempotent revoke doesn't either)", len(entries))
	}
}

// TestHandleOperator_HappyPath_AuditRowsCorrect locks the positive
// assertion that the audit rows DO get written with the verified
// resource/details when the handler succeeds. Without this, a regression
// silently removing the AddAuditEntry call would pass every existing
// negative-case test.
func TestHandleOperator_HappyPath_AuditRowsCorrect(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")
	ctx := context.Background()

	// Seed a user operator with one key.
	if err := s.CreateOperator(ctx, &models.Operator{
		ID:           "op-delta",
		Username:     "delta",
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("seed delta: %v", err)
	}
	sum := sha256.Sum256([]byte("delta-token"))
	if err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: "key-delta", OperatorID: "op-delta", Name: "d", KeyHash: hex.EncodeToString(sum[:]), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create delta key: %v", err)
	}

	exec := func(method, path string) {
		req := httptest.NewRequest(method, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		w.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s %s: status = %d, want 303; body=%s", method, path, rec.Code, rec.Body.String())
		}
	}

	// Revoke before Disable: DisableOperator cascades a revoke, which would
	// make the explicit revoke take the idempotent early-return branch and
	// skip the audit row this test is checking for.
	exec(http.MethodPost, "/ui/operators/op-delta/api-keys/key-delta/revoke")
	exec(http.MethodPost, "/ui/operators/op-delta/disable")
	exec(http.MethodPost, "/ui/operators/op-delta/enable")

	cases := []struct {
		action, resource, details string
	}{
		{"operator.disable", "op-delta", ""},
		{"operator.enable", "op-delta", ""},
		{"operator.api_key.revoke", "op-delta", "key-delta"},
	}
	for _, c := range cases {
		entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Action: c.action, Limit: 100})
		if err != nil {
			t.Fatalf("list %s: %v", c.action, err)
		}
		found := false
		for _, e := range entries {
			if e.Resource == c.resource && e.Details == c.details && e.Actor == "root" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing audit entry for action=%q resource=%q details=%q actor=root; got %d entries: %+v",
				c.action, c.resource, c.details, len(entries), entries)
		}
	}
}
