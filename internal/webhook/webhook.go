// Package webhook delivers lifecycle events (host enrolled/blocked/deleted,
// cert rotated, cert expiring, …) to an operator-configured HTTP endpoint. It
// is the unified outbound-event bus: handlers and background scanners publish
// typed events via Emit; the Dispatcher signs and delivers them asynchronously,
// off the request path, with bounded retry (#256, phase 1).
//
// Deliveries are SSRF-guarded at request time and signed with HMAC-SHA256, the
// same scheme the cert-expiry alerter already uses. The signing/guard logic
// mirrors internal/alerts and internal/config.hostIsPrivate and must stay in
// sync with them.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/uuid"
)

// HTTP headers attached to every delivery. Receivers authenticate the body via
// SignatureHeader and deduplicate on DeliveryHeader.
const (
	EventHeader     = "X-Nebula-Event"
	DeliveryHeader  = "X-Nebula-Delivery"
	SignatureHeader = "X-Nebula-Signature"
)

// Event is the envelope POSTed to the subscriber. Data carries the
// event-type-specific payload.
type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	CreatedAt time.Time      `json:"created_at"`
	Data      map[string]any `json:"data"`
}

// Emitter is the narrow interface handlers depend on so they need not know
// about delivery. *Dispatcher implements it; a nil *Dispatcher Emit is a no-op,
// so callers can hold an optional emitter without nil checks at every call site.
type Emitter interface {
	Emit(eventType string, data map[string]any)
}

// Config configures a Dispatcher. Only URL is required.
type Config struct {
	URL          string
	HMACSecret   string
	AllowPrivate bool     // permit private/loopback targets (disables the SSRF guard)
	Events       []string // delivered event types; empty means all

	// Tunables — zero values fall back to the defaults below.
	QueueSize    int
	MaxRetries   int
	RetryBackoff time.Duration
	DeliveryTO   time.Duration

	// Test seams.
	HTTPClient *http.Client     // nil => an SSRF-guarded client
	Now        func() time.Time // nil => time.Now
	NewID      func() string    // nil => "evt_"+uuid
}

const (
	defaultQueueSize    = 256
	defaultMaxRetries   = 4
	defaultRetryBackoff = 2 * time.Second
	defaultDeliveryTO   = 10 * time.Second
)

// Dispatcher signs and delivers events asynchronously. Construct with New,
// publish with Emit, and Close on shutdown to drain in-flight deliveries.
type Dispatcher struct {
	cfg     Config
	logger  *slog.Logger
	allowed map[string]bool // nil => all event types
	queue   chan Event
	client  *http.Client
	now     func() time.Time
	newID   func() string

	wg     sync.WaitGroup
	closed atomic.Bool
	done   chan struct{}
}

// New starts a Dispatcher and its delivery worker. The worker runs until Close.
func New(cfg Config, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueueSize
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = defaultRetryBackoff
	}
	if cfg.DeliveryTO <= 0 {
		cfg.DeliveryTO = defaultDeliveryTO
	}
	d := &Dispatcher{
		cfg:    cfg,
		logger: logger,
		queue:  make(chan Event, cfg.QueueSize),
		client: cfg.HTTPClient,
		now:    cfg.Now,
		newID:  cfg.NewID,
		done:   make(chan struct{}),
	}
	if d.client == nil {
		d.client = newGuardedClient(cfg.AllowPrivate, cfg.DeliveryTO)
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.newID == nil {
		d.newID = func() string { return "evt_" + uuid.NewString() }
	}
	if len(cfg.Events) > 0 {
		d.allowed = make(map[string]bool, len(cfg.Events))
		for _, e := range cfg.Events {
			d.allowed[e] = true
		}
	}
	d.wg.Add(1)
	go d.run()
	return d
}

// Emit enqueues an event for delivery. It never blocks the caller: events for
// unsubscribed types are dropped silently, and a full queue drops the event
// with a logged warning rather than stalling the request path. A nil Dispatcher
// (webhooks disabled) is a no-op.
func (d *Dispatcher) Emit(eventType string, data map[string]any) {
	if d == nil || d.closed.Load() {
		return
	}
	if d.allowed != nil && !d.allowed[eventType] {
		return
	}
	ev := Event{
		ID:        d.newID(),
		Type:      eventType,
		CreatedAt: d.now().UTC(),
		Data:      data,
	}
	select {
	case d.queue <- ev:
	default:
		d.logger.Warn("webhook queue full, dropping event", "type", eventType, "id", ev.ID)
	}
}

// Close stops accepting events and waits for the worker to drain what is
// already queued. Safe to call once; later calls are no-ops.
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	if d.closed.CompareAndSwap(false, true) {
		close(d.queue)
	}
	d.wg.Wait()
}

func (d *Dispatcher) run() {
	defer d.wg.Done()
	for ev := range d.queue {
		d.deliverWithRetry(ev)
	}
}

// deliverWithRetry attempts delivery up to MaxRetries+1 times with linear
// backoff, aborting early if Close is signaled. A permanent failure is logged
// (a dead-letter store is phase 2).
func (d *Dispatcher) deliverWithRetry(ev Event) {
	payload, err := json.Marshal(ev)
	if err != nil {
		d.logger.Error("marshal webhook event", "type", ev.Type, "error", err)
		return
	}
	for attempt := 0; attempt <= d.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(d.cfg.RetryBackoff * time.Duration(attempt)):
			case <-d.done:
				return
			}
		}
		err := d.deliver(payload, ev.Type, ev.ID)
		if err == nil {
			return
		}
		d.logger.Warn("webhook delivery failed",
			"type", ev.Type, "id", ev.ID, "attempt", attempt+1, "error", err)
	}
	d.logger.Error("webhook delivery exhausted retries", "type", ev.Type, "id", ev.ID)
}

func (d *Dispatcher) deliver(payload []byte, eventType, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.DeliveryTO)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.cfg.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(EventHeader, eventType)
	req.Header.Set(DeliveryHeader, id)
	if d.cfg.HMACSecret != "" {
		mac := hmac.New(sha256.New, []byte(d.cfg.HMACSecret))
		mac.Write(payload)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("POST: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// --- SSRF guard (mirrors internal/alerts.isBlockedWebhookAddr / config.hostIsPrivate) ---

var errPrivateWebhookAddr = errors.New("webhook delivery to private/loopback/link-local address blocked (SSRF guard); set webhooks.allow_private: true for an intentional internal sink")

func isBlockedAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified()
}

// newGuardedClient builds the delivery client. With the guard active the
// address check runs in the dialer's Control hook — after DNS resolution, on
// the literal IP — so DNS-rebinding and each redirect hop are both caught.
func newGuardedClient(allowPrivate bool, timeout time.Duration) *http.Client {
	if allowPrivate {
		return &http.Client{Timeout: timeout}
	}
	dialer := &net.Dialer{
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("webhook dial %q: %w", address, err)
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("webhook dial %q: %w", address, err)
			}
			if isBlockedAddr(addr) {
				return errPrivateWebhookAddr
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: dialer.DialContext},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("webhook: too many redirects")
			}
			return nil
		},
	}
}
