package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestPoller_PollsImmediatelyOnStart is the #228 regression: a freshly started
// poller must hit the server right away rather than waiting a full interval.
// The interval is set far longer than the run window, so any request reaching
// the server proves the immediate poll fired before the first tick.
func TestPoller_PollsImmediatelyOnStart(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_ = json.NewEncoder(w).Encode(UpdatesResponse{HasUpdates: false, Blocklist: []string{}})
	}))
	defer server.Close()

	dir := t.TempDir()
	seedSigningKeyAt(t, dir)
	p := newTestPoller(t, PollerConfig{
		ServerURL:   server.URL,
		Fingerprint: "test-fp",
		DataDir:     dir,
		Interval:    10 * time.Second, // far longer than the run window below
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = p.Run(ctx)

	if got := hits.Load(); got < 1 {
		t.Fatalf("poller made %d requests; want >= 1 immediate poll before the first %s tick", got, 10*time.Second)
	}
}
