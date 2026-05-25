package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// createUserWithAPIKey seeds a non-admin operator + API key directly via the
// store, then returns the plaintext key.
func createUserWithAPIKey(t *testing.T, srv *Server, role string) string {
	t.Helper()
	ctx := context.Background()
	op := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "non-admin-" + uuid.New().String()[:6],
		PasswordHash: "x",
		Role:         role,
	}
	if err := srv.store.CreateOperator(ctx, op); err != nil {
		t.Fatal(err)
	}
	rawKey := uuid.New().String()
	keySum := sha256.Sum256([]byte(rawKey))
	if err := srv.store.CreateOperatorAPIKey(ctx, &models.OperatorAPIKey{
		ID: uuid.New().String(), OperatorID: op.ID, KeyHash: hex.EncodeToString(keySum[:]),
	}); err != nil {
		t.Fatal(err)
	}
	return rawKey
}

func TestCreateOperator_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")

	body, _ := json.Marshal(map[string]string{"username": "bob", "password": "pw"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}

func TestCreateOperator_AdminCanCreate(t *testing.T) {
	srv, _ := newTestServer(t)
	adminKey := createUserWithAPIKey(t, srv, "admin")

	body, _ := json.Marshal(map[string]string{"username": "carol", "password": "pw"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Errorf("admin status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
}

func TestListOperators_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/operators", nil)
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}

// TestGetBlocklist_RequiresAdminRole verifies non-admin operators cannot read
// the global blocklist. Without the gate, GET /api/v1/blocklist exposes the
// fingerprints of every blocked cert across every tenant.
func TestGetBlocklist_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/blocklist", nil)
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}

func TestDisableOperator_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")
	targetOp := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "target-" + uuid.New().String()[:6],
		PasswordHash: "x",
		Role:         "user",
	}
	if err := srv.store.CreateOperator(context.Background(), targetOp); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators/"+targetOp.ID+"/disable", nil)
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}

func TestEnableOperator_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")
	targetOp := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "target-" + uuid.New().String()[:6],
		PasswordHash: "x",
		Role:         "user",
	}
	if err := srv.store.CreateOperator(context.Background(), targetOp); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators/"+targetOp.ID+"/enable", nil)
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}

func TestCreateOperatorAPIKey_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")
	targetID := createUserWithAPIKey(t, srv, "user")

	body, _ := json.Marshal(map[string]string{"name": "evil-key"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators/"+targetID+"/api-keys", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}

func TestRevokeOperatorAPIKey_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")
	targetID := createUserWithAPIKey(t, srv, "user")
	keyID := uuid.New().String()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/operators/"+targetID+"/api-keys/"+keyID, nil)
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}

func TestListOperatorAPIKeys_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")
	targetID := createUserWithAPIKey(t, srv, "user")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/operators/"+targetID+"/api-keys", nil)
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}
