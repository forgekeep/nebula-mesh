package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type received struct {
	body     []byte
	event    string
	delivery string
	sig      string
}

// recvServer returns an httptest server that pushes each received request onto
// ch and replies with status.
func recvServer(t *testing.T, ch chan received, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- received{b, r.Header.Get(EventHeader), r.Header.Get(DeliveryHeader), r.Header.Get(SignatureHeader)}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func waitRecv(t *testing.T, ch chan received) received {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery")
		return received{}
	}
}

func expectNoRecv(t *testing.T, ch chan received) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("unexpected webhook delivery: event=%s body=%s", r.event, r.body)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestDispatcher_DeliversSignedEnvelope(t *testing.T) {
	ch := make(chan received, 4)
	srv := recvServer(t, ch, http.StatusOK)

	d := New(Config{
		URL:          srv.URL,
		HMACSecret:   "s3cret",
		AllowPrivate: true, // httptest listens on loopback
		Now:          func() time.Time { return time.Unix(1_700_000_000, 0) },
		NewID:        func() string { return "evt_fixed" },
	}, testLogger())
	defer d.Close()

	d.Emit(Scope{CAID: "ca1"}, "host.enrolled", map[string]any{"host_id": "h1", "network_id": "n1"})
	got := waitRecv(t, ch)

	if got.event != "host.enrolled" {
		t.Errorf("%s header = %q, want host.enrolled", EventHeader, got.event)
	}
	if got.delivery != "evt_fixed" {
		t.Errorf("%s header = %q, want evt_fixed", DeliveryHeader, got.delivery)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(got.body)
	wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got.sig != wantSig {
		t.Errorf("signature = %q, want %q", got.sig, wantSig)
	}

	var ev Event
	if err := json.Unmarshal(got.body, &ev); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if ev.ID != "evt_fixed" || ev.Type != "host.enrolled" {
		t.Errorf("envelope id/type = %s/%s", ev.ID, ev.Type)
	}
	if !ev.CreatedAt.Equal(time.Unix(1_700_000_000, 0).UTC()) {
		t.Errorf("created_at = %s", ev.CreatedAt)
	}
	if ev.Data["host_id"] != "h1" {
		t.Errorf("data.host_id = %v, want h1", ev.Data["host_id"])
	}
	var raw map[string]any
	if err := json.Unmarshal(got.body, &raw); err != nil {
		t.Fatalf("unmarshal raw envelope: %v", err)
	}
	if _, ok := raw["scope"]; ok {
		t.Error("internal webhook scope was serialized")
	}
}

func TestDispatcher_FiltersByEventType(t *testing.T) {
	ch := make(chan received, 4)
	srv := recvServer(t, ch, http.StatusOK)

	d := New(Config{
		URL:          srv.URL,
		AllowPrivate: true,
		Events:       []string{"host.blocked"},
	}, testLogger())
	defer d.Close()

	d.Emit(Scope{}, "host.enrolled", map[string]any{"host_id": "h1"}) // not subscribed
	expectNoRecv(t, ch)

	d.Emit(Scope{}, "host.blocked", map[string]any{"host_id": "h1"}) // subscribed
	if got := waitRecv(t, ch); got.event != "host.blocked" {
		t.Errorf("delivered %q, want host.blocked", got.event)
	}
}

func TestDispatcher_RetriesUntilSuccess(t *testing.T) {
	ch := make(chan received, 8)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		n := hits.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		ch <- received{body: b, event: r.Header.Get(EventHeader)}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := New(Config{
		URL:          srv.URL,
		AllowPrivate: true,
		RetryBackoff: 10 * time.Millisecond,
		MaxRetries:   5,
	}, testLogger())
	defer d.Close()

	d.Emit(Scope{CAID: "ca1"}, "cert.rotated", map[string]any{"host_id": "h1"})
	if got := waitRecv(t, ch); got.event != "cert.rotated" {
		t.Errorf("delivered %q after retries, want cert.rotated", got.event)
	}
	if n := hits.Load(); n < 3 {
		t.Errorf("server saw %d attempts, want >= 3 (two failures then success)", n)
	}
}

func TestDispatcher_SSRFGuardBlocksLoopback(t *testing.T) {
	ch := make(chan received, 4)
	srv := recvServer(t, ch, http.StatusOK) // listens on 127.0.0.1

	// AllowPrivate false → the guarded dialer must refuse the loopback target,
	// so no retry ever reaches the server.
	d := New(Config{
		URL:          srv.URL,
		AllowPrivate: false,
		RetryBackoff: 10 * time.Millisecond,
		MaxRetries:   2,
	}, testLogger())
	defer d.Close()

	d.Emit(Scope{CAID: "ca1"}, "host.enrolled", map[string]any{"host_id": "h1"})
	expectNoRecv(t, ch)
}
