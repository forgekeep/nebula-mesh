package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/pb33f/libopenapi"
	"github.com/pb33f/libopenapi-validator/schema_validation"
	"github.com/pb33f/libopenapi/datamodel/high/base"

	"github.com/forgekeep/nebula-mesh/internal/webhook"
)

// webhookSchemas parses the spec and returns the requestBody schema for each
// documented webhook event, keyed by event type.
func webhookSchemas(t *testing.T) map[string]*base.Schema {
	t.Helper()
	specBytes, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	doc, err := libopenapi.NewDocument(specBytes)
	if err != nil {
		t.Fatalf("parse spec: %v", err)
	}
	model, err := doc.BuildV3Model()
	if err != nil {
		t.Fatalf("build model: %v", err)
	}
	if model.Model.Webhooks == nil {
		t.Fatal("spec has no webhooks block")
	}
	out := map[string]*base.Schema{}
	for pair := model.Model.Webhooks.First(); pair != nil; pair = pair.Next() {
		op := pair.Value().Post
		if op == nil || op.RequestBody == nil {
			continue
		}
		mt := op.RequestBody.Content.GetOrZero("application/json")
		if mt == nil || mt.Schema == nil {
			t.Fatalf("webhook %q missing application/json schema", pair.Key())
		}
		out[pair.Key()] = mt.Schema.Schema()
	}
	return out
}

// TestWebhookContract_EmittedPayloadsMatchSpec drives the real handlers with a
// live dispatcher, captures every delivered event, and validates each payload
// against the webhook schema documented for its type. Drift between a handler's
// emit shape and the spec breaks the build.
func TestWebhookContract_EmittedPayloadsMatchSpec(t *testing.T) {
	schemas := webhookSchemas(t)
	sv := schema_validation.NewSchemaValidator()

	type delivery struct {
		event string
		body  []byte
	}
	deliveries := make(chan delivery, 16)
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := readAllAndClose(r)
		deliveries <- delivery{event: r.Header.Get(webhook.EventHeader), body: b}
		w.WriteHeader(http.StatusOK)
	}))
	defer hookSrv.Close()

	d := webhook.New(webhook.Config{URL: hookSrv.URL, AllowPrivate: true, RetryBackoff: 10 * time.Millisecond}, nil)
	defer d.Close()

	srv, _ := newTestServer(t)
	srv.WithEventEmitter(d)

	// One host carries the whole lifecycle: enroll (host.enrolled) -> rotate
	// (cert.rotated) -> block (host.blocked) -> unblock (host.unblocked) ->
	// delete (host.deleted). enrolledFixture is the proven enroll helper.
	host := enrolledFixture(t, srv)
	id := host.hostID

	// Re-signing the same key within one wall-clock second yields an identical
	// fingerprint (second-precision certs) that collides on the UNIQUE
	// constraint; sleep so the rotation mints a distinct cert.
	time.Sleep(time.Second)
	rotReq := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+id+"/rotate-cert?new_key=false", nil)
	authRequest(rotReq)
	mustOK(t, srv, rotReq)

	for _, p := range []string{"/block", "/unblock"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/hosts/"+id+p, nil)
		authRequest(req)
		mustOK(t, srv, req)
	}
	delReq := httptest.NewRequest(http.MethodDelete, "/api/v1/hosts/"+id, nil)
	authRequest(delReq)
	if w := serve(srv, delReq); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d / %s", w.Code, w.Body.String())
	}

	// cert.expiring originates in the scanner adapter; emit a representative
	// payload (same shape the adapter produces) so its schema is exercised too.
	d.Emit("cert.expiring", map[string]any{
		"host_id": "h1", "host_name": "n", "network_id": "net1", "ca_id": "ca1",
		"fingerprint": "fp", "not_after": time.Now().UTC().Format(time.RFC3339),
		"seconds_until_expiry": 3600.0,
	})

	want := map[string]bool{
		"host.blocked": true, "host.unblocked": true, "host.deleted": true,
		"host.enrolled": true, "cert.rotated": true, "cert.expiring": true,
	}
	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for len(seen) < len(want) {
		select {
		case dlv := <-deliveries:
			schema, ok := schemas[dlv.event]
			if !ok {
				t.Errorf("delivered undocumented event %q", dlv.event)
				seen[dlv.event] = true
				continue
			}
			if valid, verrs := sv.ValidateSchemaBytes(schema, dlv.body); !valid {
				for _, e := range verrs {
					t.Errorf("%s payload violates schema: %s — %s", dlv.event, e.Message, e.Reason)
				}
			}
			seen[dlv.event] = true
		case <-deadline:
			t.Fatalf("timed out; saw %v, want %v", keys(seen), keys(want))
		}
	}
}

func mustOK(t *testing.T, srv *Server, req *http.Request) {
	t.Helper()
	if w := serve(srv, req); w.Code != http.StatusOK {
		t.Fatalf("%s %s: %d / %s", req.Method, req.URL.Path, w.Code, w.Body.String())
	}
}

func readAllAndClose(r *http.Request) ([]byte, error) {
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
