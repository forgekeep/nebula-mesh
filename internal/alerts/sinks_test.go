package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/store"
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

// TestWebhookSink_GuardedClient_BlocksPrivateAddress pins the request-time
// SSRF guard (L11, 2026-06-12 audit): with no caller-supplied client, a
// delivery that would connect to a loopback/private address fails in the
// dialer — after DNS resolution, so a hostname that resolves privately at
// delivery time is caught even if it looked public at config load.
func TestWebhookSink_GuardedClient_BlocksPrivateAddress(t *testing.T) {
	// httptest binds 127.0.0.1, exactly the class the guard must reject.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("guarded webhook client reached a loopback receiver")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := &WebhookSink{URL: srv.URL} // nil HTTPClient → guarded default
	err := sink.Notify(context.Background(), Alert{HostID: "h", NotAfter: time.Now()})
	if err == nil {
		t.Fatal("expected SSRF-guard error for loopback delivery")
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Errorf("err = %v, want SSRF-guard message", err)
	}
}

// TestWebhookSink_GuardedClient_BlocksRedirectToPrivate verifies a redirect
// to a private target is not followed there. Both hops are loopback in a
// test environment, so the outer (redirecting) hop runs with the guard
// relaxed via a transport that admits exactly its address — the redirect
// hop then dials through the guarded path and must be refused.
func TestWebhookSink_GuardedClient_BlocksRedirectToPrivate(t *testing.T) {
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("redirect target reached through SSRF guard")
		w.WriteHeader(http.StatusOK)
	}))
	defer inner.Close()

	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL, http.StatusFound)
	}))
	defer outer.Close()

	// Same client shape as newWebhookClient(false), with the dialer
	// admitting only the outer hop's address so the test can model
	// "public first hop, private redirect target" on loopback.
	guarded := newWebhookClient(false)
	transport, ok := guarded.Transport.(*http.Transport)
	if !ok {
		t.Skipf("redirect test needs a *http.Transport, got %T", guarded.Transport)
	}
	base := transport.DialContext
	outerAddr := strings.TrimPrefix(outer.URL, "http://")
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == outerAddr {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		return base(ctx, network, address)
	}

	sink := &WebhookSink{URL: outer.URL, HTTPClient: guarded}
	err := sink.Notify(context.Background(), Alert{HostID: "h", NotAfter: time.Now()})
	if err == nil {
		t.Fatal("expected SSRF-guard error on the redirect hop")
	}
	if !strings.Contains(err.Error(), "SSRF guard") {
		t.Errorf("err = %v, want SSRF-guard message", err)
	}
}

// TestWebhookSink_AllowPrivate_DeliversToLoopback pins the opt-out:
// alerts.allow_private_webhook flows into the sink and restores the
// pre-guard behavior for intentional internal receivers.
func TestWebhookSink_AllowPrivate_DeliversToLoopback(t *testing.T) {
	var delivered bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		delivered = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sink := &WebhookSink{URL: srv.URL, AllowPrivate: true}
	if err := sink.Notify(context.Background(), Alert{HostID: "h", NotAfter: time.Now()}); err != nil {
		t.Fatalf("Notify with AllowPrivate: %v", err)
	}
	if !delivered {
		t.Error("alert not delivered despite AllowPrivate")
	}
}

// TestIsBlockedWebhookAddr pins the dial-time predicate, including the
// IPv4-mapped IPv6 forms that the bare netip predicates miss (notably
// ::ffff:0.0.0.0, which routes to localhost on connect).
func TestIsBlockedWebhookAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true},
		{"0.0.0.0", true},
		{"::1", true},
		{"::", true},
		{"::ffff:127.0.0.1", true},
		{"::ffff:10.0.0.5", true},
		{"::ffff:169.254.169.254", true},
		{"::ffff:0.0.0.0", true}, // the gap the Unmap closes
		{"203.0.113.10", false},
		{"::ffff:203.0.113.10", false},
		{"2001:db8::1", false},
	}
	for _, tc := range cases {
		got := isBlockedWebhookAddr(netip.MustParseAddr(tc.addr))
		if got != tc.want {
			t.Errorf("isBlockedWebhookAddr(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
