package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// postCSRF builds and executes an authenticated POST against `path` with a
// valid CSRF token+cookie pair (minted via GET /ui/operators). Mirrors the
// inline 4-line dance used in operators_test.go, kept local so the tests
// here stay readable. The csrfMiddleware on /ui/* mutating routes (added in
// #139) rejects requests missing either piece with 403, so every POST in
// this file must go through this helper.
func postCSRF(t *testing.T, w *Web, path string, sessionCookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	token, cookies := getCSRFTokenFromCookies(t, w, "/ui/operators", []*http.Cookie{sessionCookie})
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set(csrfHeaderName, token)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)
	return rec
}

// concurrentRevokeStore wraps store.Store and injects exactly one CAS-race
// on the first GetOperatorAPIKey of a non-revoked key by revoking the row
// directly before the snapshot is returned. The handler's *models.OperatorAPIKey
// pointer still reflects RevokedAt == nil (unmarshalled before the
// wrapper's intervening UPDATE), so the handler falls past the
// RevokedAt != nil early-return and into RevokeOperatorAPIKey, which now
// returns store.ErrNotFound from the WHERE revoked_at IS NULL CAS clause.
// Exercises the TOCTOU window between GetOperatorAPIKey and the atomic CAS.
type concurrentRevokeStore struct {
	store.Store
	raceOnce sync.Once
}

func (r *concurrentRevokeStore) GetOperatorAPIKey(ctx context.Context, kid string) (*models.OperatorAPIKey, error) {
	key, err := r.Store.GetOperatorAPIKey(ctx, kid)
	if err == nil && key != nil && key.RevokedAt == nil {
		r.raceOnce.Do(func() {
			_ = r.RevokeOperatorAPIKey(ctx, kid)
		})
	}
	return key, err
}

// TestHandleOperatorDisable_NonExistent_Returns404 verifies that
// POST /ui/operators/{id}/disable with a non-existent {id} returns 404
// without writing an audit entry. Before this validation was added the
// handler 303'd to the bogus operator detail URL and wrote an
// `operator.disable` audit row with resource=<bogus id>, polluting the
// forensic record.
func TestHandleOperatorDisable_NonExistent_Returns404(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	rec := postCSRF(t, w, "/ui/operators/op-does-not-exist/disable", cookie)
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

	rec := postCSRF(t, w, "/ui/operators/op-does-not-exist/api-keys", cookie)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

// TestHandleOperatorEnable_NonExistent_Returns404 mirrors the Disable
// test for the Enable handler.
func TestHandleOperatorEnable_NonExistent_Returns404(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")

	rec := postCSRF(t, w, "/ui/operators/op-does-not-exist/enable", cookie)
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

	rec := postCSRF(t, w, "/ui/operators/op-does-not-exist/api-keys/kid-anything/revoke", cookie)
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
	rec := postCSRF(t, w, "/ui/operators/op-alpha/api-keys/key-belongs-to-beta/revoke", cookie)
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
		return postCSRF(t, w, "/ui/operators/op-gamma/api-keys/key-gamma/revoke", cookie)
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

	rec := postCSRF(t, w, "/ui/operators/op-epsilon/api-keys/key-epsilon/revoke", cookie)
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

	exec := func(path string) {
		rec := postCSRF(t, w, path, cookie)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST %s: status = %d, want 303; body=%s", path, rec.Code, rec.Body.String())
		}
	}

	// Revoke before Disable: DisableOperator cascades a revoke, which would
	// make the explicit revoke take the idempotent early-return branch and
	// skip the audit row this test is checking for.
	exec("/ui/operators/op-delta/api-keys/key-delta/revoke")
	exec("/ui/operators/op-delta/disable")
	exec("/ui/operators/op-delta/enable")

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

// TestHandleOperatorRevokeAPIKey_ConcurrentRevokeRace_Idempotent verifies
// the TOCTOU branch on the UI surface: if a concurrent revoke (another
// admin or a DisableOperator cascade) wins the CAS between the
// GetOperatorAPIKey snapshot and the RevokeOperatorAPIKey UPDATE, the
// second actor's POST must still return 303 with no new audit row,
// mirroring the RevokedAt != nil early-return path. Before the fix the
// race-loser surfaced as a 500 because store.ErrNotFound from the CAS
// clause fell into the default error branch.
func TestHandleOperatorRevokeAPIKey_ConcurrentRevokeRace_Idempotent(t *testing.T) {
	w, s := newOperatorsWeb(t)
	cookie := mintSession(t, s, "root", "admin")
	ctx := context.Background()

	if err := s.CreateOperator(ctx, &models.Operator{
		ID:           "op-race",
		Username:     "race",
		PasswordHash: "x",
		Status:       models.OperatorStatusActive,
		Role:         "user",
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}); err != nil {
		t.Fatalf("seed race: %v", err)
	}
	sum := sha256.Sum256([]byte("race-token"))
	if err := s.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: "key-race", OperatorID: "op-race", Name: "r", KeyHash: hex.EncodeToString(sum[:]), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("create race key: %v", err)
	}

	// Mint the CSRF token+cookie BEFORE swapping the store, so the GET to
	// /ui/operators (which goes through w.ServeHTTP and thus the wrapped
	// store if swapped) doesn't risk burning the race injection on an
	// unrelated lookup.
	token, allCookies := getCSRFTokenFromCookies(t, w, "/ui/operators", []*http.Cookie{cookie})

	// Swap the web's store to one that races a concurrent revoke into the
	// gap between GetOperatorAPIKey and RevokeOperatorAPIKey. Done after
	// seeding so the seed path uses the real store directly.
	w.store = &concurrentRevokeStore{Store: w.store}

	req := httptest.NewRequest(http.MethodPost, "/ui/operators/op-race/api-keys/key-race/revoke", nil)
	req.Header.Set(csrfHeaderName, token)
	for _, c := range allCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Errorf("status = %d, want 303 (idempotent on CAS-loss race)", rec.Code)
	}

	// Race-loser writes no audit row.
	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Action: "operator.api_key.revoke", Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d revoke audit entries from race-loser, want 0", len(entries))
	}

	// Key is in fact revoked (by the race injection).
	got, err := s.GetOperatorAPIKey(ctx, "key-race")
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("key should be revoked after concurrent-revoke race injection")
	}
}
