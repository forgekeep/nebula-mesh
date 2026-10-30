package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// A CA name goes into its Nebula v2 certificate, which Nebula cannot sign or
// load past models.MaxCertNameLen bytes.
func TestCreateCA_NameBoundedByCertLimit(t *testing.T) {
	srv, opKey := newServerWithMaster(t)
	create := func(name string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"name": name})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/cas", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+opKey)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	if rec := create(strings.Repeat("a", models.MaxCertNameLen)); rec.Code != http.StatusCreated {
		t.Fatalf("name at limit: status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	rec := create(strings.Repeat("b", models.MaxCertNameLen+1))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("name over limit: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "at most 253 bytes") {
		t.Errorf("body should name the limit; got %s", rec.Body.String())
	}
}
