package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestContract_WebhookSubscriptions validates the CRUD responses against the
// OpenAPI spec, so the managed-subscription API cannot drift from its contract.
func TestContract_WebhookSubscriptions(t *testing.T) {
	v := loadContract(t)
	srv, _ := newTestServer(t)

	// Create.
	body := `{"url":"https://hooks.example.com/c","events":["host.enrolled","cert.rotated"],"secret":"s3cret"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook-subscriptions", bytes.NewBufferString(body))
	authRequest(req)
	rec := serve(srv, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d / %s", rec.Code, rec.Body.String())
	}
	assertContract(t, v, req, rec)
	var sub struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)

	// List.
	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/webhook-subscriptions", nil)
	authRequest(lreq)
	assertContract(t, v, lreq, serve(srv, lreq))

	// Get.
	greq := httptest.NewRequest(http.MethodGet, "/api/v1/webhook-subscriptions/"+sub.ID, nil)
	authRequest(greq)
	assertContract(t, v, greq, serve(srv, greq))

	// Update.
	ureq := httptest.NewRequest(http.MethodPatch, "/api/v1/webhook-subscriptions/"+sub.ID,
		bytes.NewBufferString(`{"url":"https://hooks.example.com/d","active":false}`))
	authRequest(ureq)
	urec := serve(srv, ureq)
	if urec.Code != http.StatusOK {
		t.Fatalf("update: %d / %s", urec.Code, urec.Body.String())
	}
	assertContract(t, v, ureq, urec)
}
