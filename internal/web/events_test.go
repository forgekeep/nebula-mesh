package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventBus_PublishToSubscriber(t *testing.T) {
	bus := NewEventBus()
	ch, cancel := bus.Subscribe()
	defer cancel()

	go bus.Publish(HostSeenEvent{HostID: "h1", LastSeen: time.Now()})

	select {
	case ev := <-ch:
		if ev.HostID != "h1" {
			t.Errorf("host_id = %q, want h1", ev.HostID)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive event")
	}
}

func TestEventBus_Unsubscribe(t *testing.T) {
	bus := NewEventBus()
	ch, cancel := bus.Subscribe()
	cancel()

	bus.Publish(HostSeenEvent{HostID: "h1"})
	// Channel should be closed.
	select {
	case _, ok := <-ch:
		if ok {
			t.Error("expected channel to be closed after cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("channel did not close")
	}
}

func TestEventBus_SlowSubscriberDropped(t *testing.T) {
	bus := NewEventBus()
	_, cancel := bus.Subscribe()
	defer cancel()

	// Pump more events than the subscriber buffer (8). None should block.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			bus.Publish(HostSeenEvent{HostID: "h1"})
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publish blocked on slow subscriber")
	}
}

func TestHandleHostEvents_StreamsEvent(t *testing.T) {
	bus := NewEventBus()
	w := &Web{events: bus}

	// Standalone request: bypass the auth middleware since we just want
	// to test the SSE producer.
	r := httptest.NewRequest(http.MethodGet, "/ui/events", nil)
	ctx, cancel := context.WithCancel(r.Context())
	r = r.WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		w.handleHostEvents(rec, r)
		close(done)
	}()

	// Give the goroutine time to write the initial ": connected" comment
	// and subscribe.
	time.Sleep(50 * time.Millisecond)

	bus.Publish(HostSeenEvent{HostID: "h1", LastSeen: time.Now()})
	time.Sleep(50 * time.Millisecond)

	cancel()
	<-done

	body := rec.Body.String()
	if !strings.Contains(body, "event: host.seen") {
		t.Errorf("body missing host.seen event:\n%s", body)
	}
	if !strings.Contains(body, `"host_id":"h1"`) {
		t.Errorf("body missing host_id payload:\n%s", body)
	}
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("content-type = %q, want text/event-stream", rec.Header().Get("Content-Type"))
	}
}

func TestHandleHostEvents_NoBus_NotFound(t *testing.T) {
	w := &Web{}
	r := httptest.NewRequest(http.MethodGet, "/ui/events", nil)
	rec := httptest.NewRecorder()
	w.handleHostEvents(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when event bus is unset", rec.Code)
	}
}
