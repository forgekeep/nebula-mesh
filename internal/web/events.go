package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HostSeenEvent is the wire format the SSE stream pushes to each subscriber
// whenever a host's last_seen_at moves forward. The shape is intentionally
// flat so the htmx-sse swap in the Hosts table can target a specific row
// without an extra fetch.
type HostSeenEvent struct {
	HostID    string    `json:"host_id"`
	LastSeen  time.Time `json:"last_seen"`
	NetworkID string    `json:"network_id,omitempty"`
}

// EventBus is a small in-memory publish/subscribe channel for host-state
// events. The API server publishes; the Web UI's SSE handler subscribes.
// Subscribers must drain quickly — publishes drop into a buffered queue
// and stale subscribers get unblocked by dropping the event, never the
// publisher.
type EventBus struct {
	mu   sync.Mutex
	subs map[chan HostSeenEvent]struct{}
}

// NewEventBus creates a fresh bus.
func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[chan HostSeenEvent]struct{})}
}

// Publish fans the event out to every subscriber. Each subscriber's queue
// is small (8 events) so a stuck consumer drops events rather than stalling
// the agent-poll path that called Publish.
func (b *EventBus) Publish(ev HostSeenEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
			// subscriber is too slow — drop this event for them.
		}
	}
}

// Subscribe registers a new listener and returns the receive channel plus
// a cleanup func that must be called (typically via defer) when the
// subscriber is done.
func (b *EventBus) Subscribe() (<-chan HostSeenEvent, func()) {
	ch := make(chan HostSeenEvent, 8)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()

	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if _, ok := b.subs[ch]; ok {
			delete(b.subs, ch)
			close(ch)
		}
	}
	return ch, cancel
}

// WithEventBus wires the bus the SSE endpoint listens on. Must be set
// before ServeHTTP is invoked. Without a bus, /ui/events 404s.
func (w *Web) WithEventBus(bus *EventBus) {
	w.events = bus
}

// handleHostEvents streams `host.seen` SSE messages to the operator's
// browser. Each event carries a JSON HostSeenEvent so client-side code
// can patch the matching row without re-fetching the table.
func (w *Web) handleHostEvents(rw http.ResponseWriter, r *http.Request) {
	if w.events == nil {
		http.NotFound(rw, r)
		return
	}
	flusher, ok := rw.(http.Flusher)
	if !ok {
		http.Error(rw, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Scope the stream to the operator's own hosts. Admins receive every
	// event; a non-admin only receives events for networks they own — the
	// event carries the host's network_id (api/updates.go), matched against
	// the operator's accessible networks. Fail closed: an event whose network
	// the operator doesn't own (or a blank network_id) is dropped. Networks
	// created after the stream opens need a page reload to appear, which is
	// acceptable for a live-update convenience view.
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Error(rw, "unauthorized", http.StatusUnauthorized)
		return
	}
	isAdmin := op.Role == "admin"
	var ownedNetworks map[string]struct{}
	if !isAdmin {
		nets, err := w.accessibleNetworks(r.Context(), op)
		if err != nil {
			w.logger.Error("list networks for event scope", "error", err)
			http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		ownedNetworks = make(map[string]struct{}, len(nets))
		for _, n := range nets {
			ownedNetworks[n.ID] = struct{}{}
		}
	}

	rw.Header().Set("Content-Type", "text/event-stream")
	rw.Header().Set("Cache-Control", "no-cache")
	rw.Header().Set("Connection", "keep-alive")
	rw.Header().Set("X-Accel-Buffering", "no") // nginx hint
	rw.WriteHeader(http.StatusOK)

	// Initial comment so the browser knows the stream is alive.
	if _, err := fmt.Fprintf(rw, ": connected\n\n"); err != nil {
		return
	}
	flusher.Flush()

	ch, cancel := w.events.Subscribe()
	defer cancel()

	ctx := r.Context()
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			// Keep proxies from closing idle connections.
			if _, err := fmt.Fprintf(rw, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if !isAdmin {
				if _, owned := ownedNetworks[ev.NetworkID]; ev.NetworkID == "" || !owned {
					continue // not this operator's host — drop
				}
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(rw, "event: host.seen\ndata: %s\n\n", payload); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// Stop closes every active subscription. Useful in tests.
func (b *EventBus) Stop(ctx context.Context) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		delete(b.subs, ch)
		close(ch)
	}
	_ = ctx
}
