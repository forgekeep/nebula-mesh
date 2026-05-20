package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetAuditLog_RequiresAdminRole(t *testing.T) {
	srv, _ := newTestServer(t)
	userKey := createUserWithAPIKey(t, srv, "user")

	req := httptest.NewRequest("GET", "/api/v1/audit-log", nil)
	req.Header.Set("Authorization", "Bearer "+userKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin status = %d, want 403", rec.Code)
	}
}

func TestGetAuditLog_AdminSucceeds(t *testing.T) {
	srv, _ := newTestServer(t)
	adminKey := createUserWithAPIKey(t, srv, "admin")

	req := httptest.NewRequest("GET", "/api/v1/audit-log", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("admin status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}
