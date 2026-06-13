package alerts

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
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"syscall"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

// Audit action emitted by the cert-expiry alerter. Kept here as a constant
// so receivers (parsers, dashboards) can match against a stable identifier.
const AuditActionCertExpiring = "cert.expiring"

// AuditSink writes each Alert to the store's audit log as a structured
// `cert.expiring` entry. Always-on by design: the audit log is the
// no-config-required fallback documented in the issue.
type AuditSink struct {
	Store store.Store
}

// Notify appends an audit entry whose details field is a small JSON blob —
// enough for `/api/v1/audit-log` consumers to extract host_id, ca_id,
// not_after, and seconds_until_expiry without a join.
func (a *AuditSink) Notify(ctx context.Context, ev Alert) error {
	body := map[string]any{
		"host_id":              ev.HostID,
		"host_name":            ev.HostName,
		"network_id":           ev.NetworkID,
		"ca_id":                ev.CAID,
		"fingerprint":          ev.Fingerprint,
		"not_after":            ev.NotAfter.UTC().Format(time.RFC3339),
		"seconds_until_expiry": strconv.FormatFloat(ev.SecondsUntilExpiry, 'f', 0, 64),
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal audit details: %w", err)
	}
	return a.Store.AddAuditEntry(ctx, "cert-expiry-alerter", AuditActionCertExpiring, ev.HostID, string(raw))
}

// WebhookSink POSTs every alert as JSON to URL with an HMAC-SHA256 signature
// in the X-Nebula-Signature header (sha256=<hex>). If HMACSecret is empty,
// the signature header is omitted — useful for trusted-internal alertmanager
// endpoints behind mTLS where signing is redundant.
//
// Unless AllowPrivate is set, deliveries are SSRF-guarded at request time:
// the dialer rejects connections to private/loopback/link-local addresses
// after DNS resolution, and redirects re-apply the same check per hop. This
// complements the config-load check in validateWebhookURL, which cannot see
// what a hostname resolves to at delivery time or where a redirect points.
type WebhookSink struct {
	URL        string
	HMACSecret string
	HTTPClient *http.Client
	// AllowPrivate disables the request-time private-address guard,
	// mirroring alerts.allow_private_webhook for intentional internal
	// sinks. Only consulted when HTTPClient is nil — a caller-supplied
	// client manages its own transport policy.
	AllowPrivate bool
}

// SignatureHeader is the HTTP header webhook receivers should inspect to
// authenticate the request body. Exported for documentation tests.
const SignatureHeader = "X-Nebula-Signature"

func (w *WebhookSink) Notify(ctx context.Context, ev Alert) error {
	payload, err := json.Marshal(map[string]any{
		"host_id":              ev.HostID,
		"host_name":            ev.HostName,
		"network_id":           ev.NetworkID,
		"ca_id":                ev.CAID,
		"fingerprint":          ev.Fingerprint,
		"not_after":            ev.NotAfter.UTC().Format(time.RFC3339),
		"seconds_until_expiry": ev.SecondsUntilExpiry,
	})
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.HMACSecret != "" {
		mac := hmac.New(sha256.New, []byte(w.HMACSecret))
		mac.Write(payload)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	client := w.HTTPClient
	if client == nil {
		client = newWebhookClient(w.AllowPrivate)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer func() {
		// Drain the (small) body before closing so the underlying
		// connection can return to the keep-alive pool for reuse rather
		// than being discarded mid-response.
		_, _ = io.Copy(io.Discard, resp.Body)
		if err := resp.Body.Close(); err != nil {
			_ = err // status already captured; nothing actionable on close failure
		}
	}()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// errPrivateWebhookAddr is returned by the guarded dialer when a webhook
// delivery would connect to a non-public address.
var errPrivateWebhookAddr = errors.New("webhook delivery to private/loopback/link-local address blocked (SSRF guard); set alerts.allow_private_webhook: true for an intentional internal sink")

// isBlockedWebhookAddr reports whether addr is a non-public destination the
// webhook guard must refuse: loopback, private, link-local, or unspecified.
// An IPv4-mapped IPv6 address is first unmapped to its v4 form — netip's
// predicates classify most mapped forms correctly, but ::ffff:0.0.0.0 reads
// as non-unspecified while 0.0.0.0 routes to localhost on connect, so Unmap
// makes the check form-independent. Mirrors config.hostIsPrivate; the two
// must stay in sync.
func isBlockedWebhookAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsUnspecified()
}

// newWebhookClient builds the sink's default HTTP client. With the guard
// active (allowPrivate false), the address check runs in the dialer's
// Control hook — after DNS resolution, on the literal IP being connected
// to — so a hostname that was public at config load but resolves privately
// at delivery time (DNS rebinding), and any redirect hop, are both caught.
// CheckRedirect re-applies because each redirect triggers a fresh dial
// through the same transport; the explicit hop cap mirrors http's default.
func newWebhookClient(allowPrivate bool) *http.Client {
	if allowPrivate {
		return &http.Client{Timeout: 10 * time.Second}
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
			if isBlockedWebhookAddr(addr) {
				return errPrivateWebhookAddr
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("webhook: too many redirects")
			}
			// Each hop dials through the guarded transport, so the
			// private-address check re-applies automatically; nothing
			// further to validate here.
			return nil
		},
	}
}
