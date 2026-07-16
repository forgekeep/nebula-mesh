package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnrollRejectsMeshImportTokenBeforeStoreLookup(t *testing.T) {
	srv, _ := newTestServer(t)
	body, _ := json.Marshal(enrollRequest{
		Token: "nmi_not-an-enrollment-token", PublicKeyPEM: "unused", SigningPubPEM: "unused",
	})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	response := httptest.NewRecorder()
	srv.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body = %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "purpose") {
		t.Fatalf("response does not identify purpose mismatch: %s", response.Body.String())
	}
}
