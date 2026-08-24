// Package webhook delivers lifecycle events (host enrolled/blocked/deleted,
// cert rotated, cert expiring, …) to operator-configured HTTP endpoints. It is
// the unified outbound-event bus: handlers and background scanners publish typed
// events via Emit; the Dispatcher signs and delivers them asynchronously, off
// the request path, with bounded retry (#256).
//
// Targets come from two places: an optional static target from server config
// (phase 1) and managed subscriptions loaded from a SubscriptionSource
// (phase 2). Deliveries are SSRF-guarded at request time and signed with
// HMAC-SHA256. The signing/guard logic mirrors internal/alerts and
// internal/config.hostIsPrivate and must stay in sync with them.
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
	"uuid"
)

// HTTP headers attached to every delivery. Receivers authenticate the body via
// SignatureHeader and deduplicate on DeliveryHeader.
const (
	EventHeader     = "X-Nebula-Event"
	DeliveryHeader  = "X-Nebula-Delivery"
	SignatureHeader = "X-Nebula-Signature"
)

// Scope identifies the CA tenant for managed-subscription routing. It is
// internal delivery metadata and is never serialized to webhook receivers.
type Scope struct {
	CAID string
}

// Event is the envelope POSTed to a subscriber. Data carries the
// event-type-specific payload.
type Event struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	CreatedAt time.Time      `json:"created_at"`
	Data      map[string]any `json:"data"`
	Scope     Scope          `json:"-"`
}

// Emitter is the narrow interface handlers depend on. *Dispatcher implements
// it; a nil *Dispatcher Emit is a no-op.
type Emitter interface {
	Emit(scope Scope, eventType string, data map[string]any)
}

// Target is one resolved delivery endpoint. ID is the subscription id for
// managed targets (delivery status is recorded against it) and empty for the
// static config target.
type Target struct {
	ID           string
	URL          string
	Secret       []byte // HMAC secret; empty => unsigned
	AllowPrivate bool
}

// SubscriptionSource yields managed subscriptions for an event and records the
// outcome of each delivery.
type SubscriptionSource interface {
	TargetsFor(ctx context.Context, scope Scope, eventType string) ([]Target, error)
	RecordDelivery(ctx context.Context, targetID string, ok bool, errMsg string)
}

// Config configures a Dispatcher. A static target is delivered when URL is set
// (phase-1 config webhook); managed targets come from Source.
type Config struct {
	// Static config target (optional).
	URL          string
	HMACSecret   string
	AllowPrivate bool
	Events       []string // static target's event filter; empty = all

	// Managed subscriptions (optional).
	Source SubscriptionSource

	// Tunables — zero values fall back to the defaults below.
	QueueSize    int
	MaxRetries   int
	RetryBackoff time.Duration
	DeliveryTO   time.Duration

	// Test seams.
	HTTPClient *http.Client     // overrides both guarded/unguarded clients
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
	cfg          Config
	logger       *slog.Logger
	source       SubscriptionSource
	staticEvents map[string]bool // nil => all; only consulted when cfg.URL != ""
	guarded      *http.Client
	unguarded    *http.Client
	now          func() time.Time
	newID        func() string
	staticSecret []byte // cached HMAC secret for the static config target (#297)

	queue  chan Event
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
		source: cfg.Source,
		now:    cfg.Now,
		newID:  cfg.NewID,
		queue:  make(chan Event, cfg.QueueSize),
		done:   make(chan struct{}),
	}
	if cfg.HTTPClient != nil {
		d.guarded, d.unguarded = cfg.HTTPClient, cfg.HTTPClient
	} else {
		d.guarded = newGuardedClient(false, cfg.DeliveryTO)
		d.unguarded = newGuardedClient(true, cfg.DeliveryTO)
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.newID == nil {
		d.newID = func() string { return "evt_" + uuid.NewV4().String() }
	}
	if len(cfg.Events) > 0 {
		d.staticEvents = make(map[string]bool, len(cfg.Events))
		for _, e := range cfg.Events {
			d.staticEvents[e] = true
		}
	}
	if cfg.HMACSecret != "" {
		d.staticSecret = []byte(cfg.HMACSecret)
	}
	d.wg.Add(1)
	go d.run()
	return d
}

// Emit enqueues an event. It never blocks the caller: a full queue drops the
// event with a logged warning rather than stalling the request path. Per-target
// filtering happens at delivery. A nil Dispatcher (webhooks disabled) is a no-op.
func (d *Dispatcher) Emit(scope Scope, eventType string, data map[string]any) {
	if d == nil || d.closed.Load() {
		return
	}
	ev := Event{
		ID:        d.newID(),
		Type:      eventType,
		CreatedAt: d.now().UTC(),
		Data:      data,
		Scope:     scope,
	}
	select {
	case d.queue <- ev:
	default:
		d.logger.Warn("webhook queue full, dropping event", "type", eventType, "id", ev.ID)
	}
}

// Close stops accepting events and drains what is already queued. Idempotent.
func (d *Dispatcher) Close() {
	if d == nil {
		return
	}
	if d.closed.CompareAndSwap(false, true) {
		close(d.queue)
	}
	clear(d.staticSecret)
	d.wg.Wait()
}

func (d *Dispatcher) run() {
	defer d.wg.Done()
	for ev := range d.queue {
		d.dispatch(ev)
	}
}

// dispatch resolves every target for the event and delivers to each.
func (d *Dispatcher) dispatch(ev Event) {
	payload, err := json.Marshal(ev)
	if err != nil {
		d.logger.Error("marshal webhook event", "type", ev.Type, "error", err)
		return
	}
	for _, tgt := range d.targets(ev.Scope, ev.Type) {
		d.deliverWithRetry(tgt, payload, ev.Type, ev.ID)
	}
}

// targets gathers the static config target (when it wants the event) and any
// managed subscriptions from the source.
func (d *Dispatcher) targets(scope Scope, eventType string) []Target {
	var out []Target
	if d.cfg.URL != "" && (d.staticEvents == nil || d.staticEvents[eventType]) {
		out = append(out, Target{URL: d.cfg.URL, Secret: d.staticSecret, AllowPrivate: d.cfg.AllowPrivate})
	}
	if d.source != nil {
		ctx, cancel := context.WithTimeout(context.Background(), d.cfg.DeliveryTO)
		subs, err := d.source.TargetsFor(ctx, scope, eventType)
		cancel()
		if err != nil {
			d.logger.Error("load webhook subscriptions", "type", eventType, "error", err)
		} else {
			out = append(out, subs...)
		}
	}
	return out
}

// deliverWithRetry attempts delivery up to MaxRetries+1 times with linear
// backoff, aborting early if Close is signaled. The final outcome is recorded
// against the subscription (managed targets only).
func (d *Dispatcher) deliverWithRetry(tgt Target, payload []byte, eventType, id string) {
	// Zeroize the decrypted HMAC secret after all delivery attempts.
	// The static config secret is shared (cached in d.staticSecret) and
	// zeroized in Close(); managed secrets are per-delivery copies (#297).
	if tgt.ID != "" {
		defer clear(tgt.Secret)
	}
	var lastErr error
	for attempt := 0; attempt <= d.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(d.cfg.RetryBackoff * time.Duration(attempt)):
			case <-d.done:
				return
			}
		}
		if lastErr = d.deliver(tgt, payload, eventType, id); lastErr == nil {
			d.record(tgt, true, "")
			return
		}
		d.logger.Warn("webhook delivery failed",
			"target", tgt.URL, "type", eventType, "id", id, "attempt", attempt+1, "error", lastErr)
	}
	d.logger.Error("webhook delivery exhausted retries", "target", tgt.URL, "type", eventType, "id", id)
	d.record(tgt, false, lastErr.Error())
}

func (d *Dispatcher) record(tgt Target, ok bool, errMsg string) {
	if tgt.ID == "" || d.source == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.DeliveryTO)
	defer cancel()
	d.source.RecordDelivery(ctx, tgt.ID, ok, errMsg)
}

func (d *Dispatcher) deliver(tgt Target, payload []byte, eventType, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), d.cfg.DeliveryTO)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tgt.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(EventHeader, eventType)
	req.Header.Set(DeliveryHeader, id)
	if len(tgt.Secret) > 0 {
		mac := hmac.New(sha256.New, tgt.Secret)
		mac.Write(payload)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	client := d.guarded
	if tgt.AllowPrivate {
		client = d.unguarded
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// --- SSRF guard (mirrors internal/alerts.isBlockedWebhookAddr / config.hostIsPrivate) ---

var errPrivateWebhookAddr = errors.New("webhook delivery to private/loopback/link-local address blocked (SSRF guard); set allow_private: true for an intentional internal sink")

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
