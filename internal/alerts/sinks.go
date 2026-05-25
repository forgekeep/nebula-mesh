package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
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
type WebhookSink struct {
	URL        string
	HMACSecret string
	HTTPClient *http.Client
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
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// nothing meaningful to do — drain failed but the upstream
			// status was already captured.
			_ = err
		}
	}()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
