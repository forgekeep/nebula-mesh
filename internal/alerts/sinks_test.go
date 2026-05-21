package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juev/nebula-mesh/internal/store"
)

func TestAuditSink_WritesEntry(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	netID := seedNetwork(t, s)
	seedEnrolledHost(t, s, "ha", netID, "fp", time.Now(), time.Now().Add(2*time.Hour))

	sink := &AuditSink{Store: s}
	ev := Alert{
		HostID:             "ha",
		HostName:           "ha",
		NetworkID:          netID,
		CAID:               "ca-test",
		Fingerprint:        "fp",
		NotAfter:           time.Now().Add(2 * time.Hour),
		SecondsUntilExpiry: 7200,
	}
	if err := sink.Notify(ctx, ev); err != nil {
		t.Fatal(err)
	}

	entries, err := s.ListAuditEntries(ctx, store.AuditFilter{Action: AuditActionCertExpiring, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries: got %d, want 1", len(entries))
	}
	if entries[0].Action != AuditActionCertExpiring {
		t.Errorf("action = %q, want %q", entries[0].Action, AuditActionCertExpiring)
	}
	if entries[0].Resource != "ha" {
		t.Errorf("resource = %q, want host id", entries[0].Resource)
	}
	if !strings.Contains(entries[0].Details, `"ca_id":"ca-test"`) {
		t.Errorf("details missing ca_id: %s", entries[0].Details)
	}
}

func TestWebhookSink_PostsSignedPayload(t *testing.T) {
	var (
		mu      sync.Mutex
		gotBody []byte
		gotSig  string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotBody = body
		gotSig = r.Header.Get(SignatureHeader)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := &WebhookSink{URL: srv.URL, HMACSecret: "shh", HTTPClient: srv.Client()}
	ev := Alert{
		HostID:             "h1",
		HostName:           "name-1",
		NetworkID:          "n1",
		CAID:               "ca-1",
		Fingerprint:        "fp-1",
		NotAfter:           time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		SecondsUntilExpiry: 3600,
	}
	if err := sink.Notify(context.Background(), ev); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(gotBody) == 0 {
		t.Fatal("webhook receiver got no body")
	}
	var decoded map[string]any
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("invalid JSON body: %v\n%s", err, string(gotBody))
	}
	if decoded["host_id"] != "h1" {
		t.Errorf("host_id = %v, want h1", decoded["host_id"])
	}
	if decoded["not_after"] != "2026-06-01T00:00:00Z" {
		t.Errorf("not_after = %v, want 2026-06-01T00:00:00Z", decoded["not_after"])
	}

	expectMAC := hmac.New(sha256.New, []byte("shh"))
	expectMAC.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(expectMAC.Sum(nil))
	if gotSig != want {
		t.Errorf("signature header = %q, want %q", gotSig, want)
	}
}

func TestWebhookSink_NoSecret_NoSignature(t *testing.T) {
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get(SignatureHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := &WebhookSink{URL: srv.URL, HTTPClient: srv.Client()}
	if err := sink.Notify(context.Background(), Alert{HostID: "h", NotAfter: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if sig != "" {
		t.Errorf("expected no signature header when secret is empty, got %q", sig)
	}
}

func TestWebhookSink_ReceiverError_PropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sink := &WebhookSink{URL: srv.URL, HTTPClient: srv.Client()}
	err := sink.Notify(context.Background(), Alert{HostID: "h", NotAfter: time.Now()})
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected error mentioning HTTP 500, got %v", err)
	}
}
