package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// concurrentRevokeStore wraps store.Store and injects exactly one CAS-race
// on the first GetOperatorAPIKey of a non-revoked key by revoking the row
// directly before the snapshot is returned. The handler's *models.OperatorAPIKey
// pointer still reflects RevokedAt == nil (since it was unmarshalled before
// the wrapper's intervening UPDATE), so the handler falls through past the
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

// seedOperatorWithKey seeds an operator + one API key and returns both ids
// plus the raw token (caller usually only needs the ids). Distinct from
// createUserWithAPIKey, which throws away the operator and key ids and
// only returns the raw token — useful for admin-bearer-auth but not for
// tests that need to address the seeded operator/key via URL paths.
func seedOperatorWithKey(t *testing.T, srv *Server, username, role string) (operatorID, keyID, rawKey string) {
	t.Helper()
	ctx := context.Background()
	op := &models.Operator{
		ID:           "op-" + username,
		Username:     "user-" + username,
		PasswordHash: "x",
		Role:         role,
	}
	if err := srv.store.CreateOperator(ctx, op); err != nil {
		t.Fatalf("create operator %s: %v", username, err)
	}
	rawKey = uuid.New().String()
	keySum := sha256.Sum256([]byte(rawKey))
	key := &models.OperatorAPIKey{
		ID:         "key-" + username,
		OperatorID: op.ID,
		KeyHash:    hex.EncodeToString(keySum[:]),
	}
	if err := srv.store.CreateOperatorAPIKey(ctx, key); err != nil {
		t.Fatalf("create api key %s: %v", username, err)
	}
	return op.ID, key.ID, rawKey
}

// TestAPI_HandleRevokeOperatorAPIKey_NonExistentOperator_Returns404
// verifies the JSON API mirrors the UI fix: a DELETE against a bogus {id}
// returns 404 and writes no audit row.
func TestAPI_HandleRevokeOperatorAPIKey_NonExistentOperator_Returns404(t *testing.T) {
	srv, _ := newTestServer(t)
	adminKey := createUserWithAPIKey(t, srv, "admin")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/operators/op-does-not-exist/api-keys/anything", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}

	entries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{Action: auditOperatorAPIKeyRevoke, Limit: 100})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	for _, e := range entries {
		if e.Resource == "op-does-not-exist" {
			t.Errorf("unexpected audit entry for non-existent operator: %+v", e)
		}
	}
}

// TestAPI_HandleRevokeOperatorAPIKey_KidBelongsToDifferentOperator_Returns404
// verifies the API rejects a cross-operator kid and does NOT revoke the
// real owner's key. Same audit-integrity invariant the UI fix locks.
func TestAPI_HandleRevokeOperatorAPIKey_KidBelongsToDifferentOperator_Returns404(t *testing.T) {
	srv, _ := newTestServer(t)
	adminKey := createUserWithAPIKey(t, srv, "admin")

	alphaID, _, _ := seedOperatorWithKey(t, srv, "alpha", "user")
	_, betaKeyID, _ := seedOperatorWithKey(t, srv, "beta", "user")

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/operators/"+alphaID+"/api-keys/"+betaKeyID, nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}

	// Beta's key must NOT be revoked.
	got, err := srv.store.GetOperatorAPIKey(context.Background(), betaKeyID)
	if err != nil {
		t.Fatalf("get beta key: %v", err)
	}
	if got.RevokedAt != nil {
		t.Errorf("beta's key was unexpectedly revoked (revoked_at=%v)", got.RevokedAt)
	}

	// No audit row under alpha.
	entries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{Action: auditOperatorAPIKeyRevoke, Limit: 100})
	if err != nil {
		t.Fatalf("list audit entries: %v", err)
	}
	for _, e := range entries {
		if e.Resource == alphaID {
			t.Errorf("unexpected audit entry under alpha for cross-operator kid: %+v", e)
		}
	}
}

// TestAPI_HandleRevokeOperatorAPIKey_AfterDisableCascade_Idempotent
// verifies the API-side early-return-on-revoked branch via the
// DisableOperator cascade path (key is auto-revoked, then admin tries an
// explicit DELETE). Must return 204 with no new audit row.
func TestAPI_HandleRevokeOperatorAPIKey_AfterDisableCascade_Idempotent(t *testing.T) {
	srv, _ := newTestServer(t)
	adminKey := createUserWithAPIKey(t, srv, "admin")
	opID, keyID, _ := seedOperatorWithKey(t, srv, "epsilon", "user")

	if err := srv.store.DisableOperator(context.Background(), opID); err != nil {
		t.Fatalf("disable: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/operators/"+opID+"/api-keys/"+keyID, nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (idempotent after cascade revoke)", rec.Code)
	}
	entries, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{Action: auditOperatorAPIKeyRevoke, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d revoke audit entries, want 0 (cascade doesn't audit each key; idempotent revoke doesn't either)", len(entries))
	}
}

// TestAPI_HandleRevokeOperatorAPIKey_AlreadyRevoked_Idempotent verifies
// the API returns 204 idempotently for a re-revoke of the same kid (after
// either an explicit prior revoke or a DisableOperator cascade), and
// writes no new audit row.
func TestAPI_HandleRevokeOperatorAPIKey_AlreadyRevoked_Idempotent(t *testing.T) {
	srv, _ := newTestServer(t)
	adminKey := createUserWithAPIKey(t, srv, "admin")
	opID, keyID, _ := seedOperatorWithKey(t, srv, "gamma", "user")

	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete,
			"/api/v1/operators/"+opID+"/api-keys/"+keyID, nil)
		req.Header.Set("Authorization", "Bearer "+adminKey)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	if rec := post(); rec.Code != http.StatusNoContent {
		t.Fatalf("first revoke: status = %d, want 204", rec.Code)
	}
	first, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{Action: auditOperatorAPIKeyRevoke, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("after first revoke: %d audit entries, want 1", len(first))
	}

	if rec := post(); rec.Code != http.StatusNoContent {
		t.Errorf("second revoke: status = %d, want 204 (idempotent)", rec.Code)
	}
	second, err := srv.store.ListAuditEntries(context.Background(), store.AuditFilter{Action: auditOperatorAPIKeyRevoke, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 {
		t.Errorf("after second revoke: %d audit entries, want 1 (no new row for idempotent re-revoke)", len(second))
	}
}

// TestAPI_HandleRevokeOperatorAPIKey_ConcurrentRevokeRace_Idempotent
// verifies the TOCTOU branch added on top of the GetOperatorAPIKey →
// RevokeOperatorAPIKey sequence: if a concurrent revoke (another admin or
// a DisableOperator cascade) wins the CAS between the lookup and the
// UPDATE, the second actor's call must still return 204 with no new
// audit row, mirroring the RevokedAt != nil early-return path. Before
// the fix the race-loser surfaced as a 500 because store.ErrNotFound
// from the CAS clause fell into the default error branch.
func TestAPI_HandleRevokeOperatorAPIKey_ConcurrentRevokeRace_Idempotent(t *testing.T) {
	srv, base := newTestServer(t)
	adminKey := createUserWithAPIKey(t, srv, "admin")
	opID, keyID, _ := seedOperatorWithKey(t, srv, "race", "user")

	// Swap the server's store to one that races a concurrent revoke into
	// the gap between GetOperatorAPIKey and RevokeOperatorAPIKey. Done
	// after seeding so the seed path uses the real store directly.
	srv.store = &concurrentRevokeStore{Store: srv.store}

	req := httptest.NewRequest(http.MethodDelete,
		"/api/v1/operators/"+opID+"/api-keys/"+keyID, nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204 (idempotent on CAS-loss race)", rec.Code)
	}

	// Race-loser writes no audit row — only the race-winning revoke (which
	// in this test was the wrapper's direct store call, intentionally
	// bypassing audit) caused the state change.
	entries, err := base.ListAuditEntries(context.Background(), store.AuditFilter{Action: auditOperatorAPIKeyRevoke, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d revoke audit entries from race-loser, want 0", len(entries))
	}

	// Key is in fact revoked (by the race injection).
	got, err := base.GetOperatorAPIKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("get key: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("key should be revoked after concurrent-revoke race injection")
	}
}
