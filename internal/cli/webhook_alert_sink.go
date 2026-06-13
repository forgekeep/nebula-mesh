package cli

import (
	"context"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/alerts"
	"github.com/forgekeep/nebula-mesh/internal/webhook"
)

// certExpiryWebhookSink adapts the cert-expiry alerter's Sink interface onto the
// unified webhook bus: each cert-expiry alert is emitted as a `cert.expiring`
// event (#256), so it flows through the same signing secret, event-type filter,
// and retry path as the handler-driven lifecycle events.
type certExpiryWebhookSink struct {
	dispatcher *webhook.Dispatcher
}

func (s certExpiryWebhookSink) Notify(_ context.Context, a alerts.Alert) error {
	s.dispatcher.Emit("cert.expiring", map[string]any{
		"host_id":              a.HostID,
		"host_name":            a.HostName,
		"network_id":           a.NetworkID,
		"ca_id":                a.CAID,
		"fingerprint":          a.Fingerprint,
		"not_after":            a.NotAfter.UTC().Format(time.RFC3339),
		"seconds_until_expiry": a.SecondsUntilExpiry,
	})
	return nil
}
