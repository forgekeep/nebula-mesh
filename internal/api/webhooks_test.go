package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

func createWebhookSub(t *testing.T, srv *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook-subscriptions", bytes.NewBufferString(body))
	authRequest(req)
	return serve(srv, req)
}

func TestWebhookSubscriptions_CRUD(t *testing.T) {
	srv, _ := newTestServer(t)

	// Create with a signing secret.
	rec := createWebhookSub(t, srv, `{"url":"https://hooks.example.com/a","events":["host.enrolled"],"secret":"s3cret"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d / %s", rec.Code, rec.Body.String())
	}
	// The secret must never echo back, but HasSecret must be true.
	var raw map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &raw)
	if _, leaked := raw["secret"]; leaked {
		t.Error("response leaked the secret")
	}
	if hs, _ := raw["has_secret"].(bool); !hs {
		t.Errorf("has_secret = %v, want true", raw["has_secret"])
	}
	var sub models.WebhookSubscription
	_ = json.Unmarshal(rec.Body.Bytes(), &sub)
	if sub.ID == "" || !sub.Active {
		t.Fatalf("unexpected created sub: %+v", sub)
	}

	// List includes it.
	lreq := httptest.NewRequest(http.MethodGet, "/api/v1/webhook-subscriptions", nil)
	authRequest(lreq)
	lrec := serve(srv, lreq)
	var list []models.WebhookSubscription
	_ = json.Unmarshal(lrec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != sub.ID {
		t.Fatalf("list = %+v", list)
	}

	// Get.
	greq := httptest.NewRequest(http.MethodGet, "/api/v1/webhook-subscriptions/"+sub.ID, nil)
	authRequest(greq)
	if grec := serve(srv, greq); grec.Code != http.StatusOK {
		t.Fatalf("get: %d", grec.Code)
	}

	// Update: clear the secret and deactivate.
	ureq := httptest.NewRequest(http.MethodPatch, "/api/v1/webhook-subscriptions/"+sub.ID,
		bytes.NewBufferString(`{"url":"https://hooks.example.com/b","active":false,"secret":""}`))
	authRequest(ureq)
	urec := serve(srv, ureq)
	if urec.Code != http.StatusOK {
		t.Fatalf("update: %d / %s", urec.Code, urec.Body.String())
	}
	var updated models.WebhookSubscription
	_ = json.Unmarshal(urec.Body.Bytes(), &updated)
	if updated.URL != "https://hooks.example.com/b" || updated.Active || updated.HasSecret {
		t.Errorf("update not applied: %+v", updated)
	}

	// Delete.
	dreq := httptest.NewRequest(http.MethodDelete, "/api/v1/webhook-subscriptions/"+sub.ID, nil)
	authRequest(dreq)
	if drec := serve(srv, dreq); drec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", drec.Code)
	}
	greq2 := httptest.NewRequest(http.MethodGet, "/api/v1/webhook-subscriptions/"+sub.ID, nil)
	authRequest(greq2)
	if grec2 := serve(srv, greq2); grec2.Code != http.StatusNotFound {
		t.Errorf("get after delete: %d, want 404", grec2.Code)
	}
}

func TestWebhookSubscriptions_RejectsPrivateURL(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := createWebhookSub(t, srv, `{"url":"http://127.0.0.1:9000/hook"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with loopback url: %d, want 400", rec.Code)
	}
	// allow_private opts in.
	rec2 := createWebhookSub(t, srv, `{"url":"http://127.0.0.1:9000/hook","allow_private":true}`)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("create with allow_private: %d / %s", rec2.Code, rec2.Body.String())
	}
}

func TestWebhookSubscriptions_GetNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webhook-subscriptions/missing", nil)
	authRequest(req)
	if rec := serve(srv, req); rec.Code != http.StatusNotFound {
		t.Errorf("get missing: %d, want 404", rec.Code)
	}
}
