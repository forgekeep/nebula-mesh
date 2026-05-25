package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestOperatorLifecycle_CreateListDisable(t *testing.T) {
	srv, st := newTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"username": "bob", "password": "supersecret", "display_name": "Bob",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators", bytes.NewBuffer(body))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var created models.Operator
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Username != "bob" {
		t.Errorf("username = %q, want bob", created.Username)
	}

	// List should include bob
	req = httptest.NewRequest(http.MethodGet, "/api/v1/operators", nil)
	authRequest(req)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list operators = %d", rec.Code)
	}
	var list []models.Operator
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range list {
		if o.Username == "bob" {
			found = true
		}
	}
	if !found {
		t.Error("created operator not in list response")
	}

	// Disable bob
	req = httptest.NewRequest(http.MethodPost, "/api/v1/operators/"+created.ID+"/disable", nil)
	authRequest(req)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("disable status = %d", rec.Code)
	}
	got, _ := st.GetOperator(context.Background(), created.ID)
	if got.Status != models.OperatorStatusDisabled {
		t.Errorf("status after disable = %q", got.Status)
	}
}

func TestOperatorAPIKey_CreateAndUse(t *testing.T) {
	srv, _ := newTestServer(t)

	body, _ := json.Marshal(map[string]string{
		"username": "carol", "password": "secret123",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators", bytes.NewBuffer(body))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d", rec.Code)
	}
	var op models.Operator
	if err := json.NewDecoder(rec.Body).Decode(&op); err != nil {
		t.Fatal(err)
	}

	// Create API key
	req = httptest.NewRequest(http.MethodPost, "/api/v1/operators/"+op.ID+"/api-keys", bytes.NewBufferString(`{"name":"cli"}`))
	authRequest(req)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create api key status = %d; body=%s", rec.Code, rec.Body.String())
	}
	var keyResp createAPIKeyResponse
	if err := json.NewDecoder(rec.Body).Decode(&keyResp); err != nil {
		t.Fatal(err)
	}
	if keyResp.Key == "" {
		t.Fatal("plaintext key is empty")
	}
	// The plain key length is 64 (32 bytes hex)
	if _, err := hex.DecodeString(keyResp.Key); err != nil {
		t.Errorf("key is not hex: %v", err)
	}

	// Use the new key to access a protected endpoint
	req = httptest.NewRequest(http.MethodGet, "/api/v1/operators", nil)
	req.Header.Set("Authorization", "Bearer "+keyResp.Key)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("using new key: status = %d", rec.Code)
	}

	// Revoke it
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/operators/"+op.ID+"/api-keys/"+keyResp.Entry.ID, nil)
	authRequest(req)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("revoke status = %d", rec.Code)
	}

	// Now the key should not authenticate
	req = httptest.NewRequest(http.MethodGet, "/api/v1/operators", nil)
	req.Header.Set("Authorization", "Bearer "+keyResp.Key)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("revoked key status = %d, want 401", rec.Code)
	}
}

func TestDisableOperator_InvalidatesAPIKey(t *testing.T) {
	srv, st := newTestServer(t)

	// Create operator
	body, _ := json.Marshal(map[string]string{"username": "dan", "password": "p"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators", bytes.NewBuffer(body))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var op models.Operator
	_ = json.NewDecoder(rec.Body).Decode(&op)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/operators/"+op.ID+"/api-keys", bytes.NewBufferString(`{}`))
	authRequest(req)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var keyResp createAPIKeyResponse
	_ = json.NewDecoder(rec.Body).Decode(&keyResp)

	// Disable
	if err := st.DisableOperator(context.Background(), op.ID); err != nil {
		t.Fatal(err)
	}

	// Key should no longer authenticate
	req = httptest.NewRequest(http.MethodGet, "/api/v1/operators", nil)
	req.Header.Set("Authorization", "Bearer "+keyResp.Key)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestAuditLogActorIsRecorded(t *testing.T) {
	srv, st := newTestServer(t)

	body, _ := json.Marshal(map[string]string{"username": "eve", "password": "p"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/operators", bytes.NewBuffer(body))
	authRequest(req)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create operator status = %d", rec.Code)
	}

	entries, err := st.ListAuditEntries(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Action == "operator.create" && e.Actor == "admin" {
			found = true
		}
	}
	if !found {
		t.Error("audit entry for operator.create with actor=admin not found")
	}
}
