// Package alerts implements the cert-expiry alerter: a periodic scanner that
// detects host certificates approaching their expiry without having been
// auto-renewed and fans the event out to one or more sinks (audit log,
// webhook, Prometheus gauge).
//
// State lives in the cert_alerts table — one row per host — so a given
// (host, not_after) pair fires at most once even if the scan tick fires
// many times before someone rotates the cert.
package alerts

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

// Alert is the structured event a Sink receives.
type Alert struct {
	HostID             string
	HostName           string
	NetworkID          string
	CAID               string
	Fingerprint        string
	NotAfter           time.Time
	SecondsUntilExpiry float64
}

// Sink is the interface implemented by alert delivery backends — audit log,
// webhook, Prometheus gauge, etc. A sink's Notify call is expected to be
// fast and best-effort; the scanner records the alert as fired regardless
// of individual sink failures so a flaky webhook does not block the audit
// log entry or trigger duplicate delivery on the next scan tick.
type Sink interface {
	Notify(ctx context.Context, a Alert) error
}

// Scanner is a periodic cert-expiry watchdog. Wire one up at server start,
// call StartLoop with a cancellable context, and it ticks every Interval
// until the context is cancelled.
type Scanner struct {
	Store     store.Store
	Threshold time.Duration
	Interval  time.Duration
	Sinks     []Sink
	Logger    *slog.Logger
}

// Run performs a single sweep: enumerate enrolled hosts' current certs,
// filter to those whose remaining lifetime is shorter than Threshold, and
// emit one Alert per (host, not_after) pair that has not yet been alerted.
//
// Errors from individual sinks are logged but do not stop the loop; the
// dedup record is still written so retries happen at the next threshold
// crossing (cert rotation) rather than every tick.
func (s *Scanner) Run(ctx context.Context) error {
	certs, err := s.Store.ListEnrolledHostCerts(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	cutoff := now.Add(s.Threshold)
	for _, ci := range certs {
		if ci.NotAfter.After(cutoff) {
			continue
		}

		prev, getErr := s.Store.GetCertAlert(ctx, ci.HostID)
		if getErr != nil && !errors.Is(getErr, store.ErrNotFound) {
			s.logger().Error("get prior cert alert", "host", ci.HostID, "error", getErr)
			continue
		}
		if getErr == nil && prev.Equal(ci.NotAfter) {
			// Already alerted for this exact expiry instant — wait for
			// rotation (which mints a new not_after) or cert removal.
			continue
		}

		host, hostErr := s.Store.GetHost(ctx, ci.HostID)
		if hostErr != nil {
			s.logger().Error("get host for alert", "host", ci.HostID, "error", hostErr)
			continue
		}
		// Defence in depth: ListEnrolledHostCerts already filters by
		// status=enrolled, but a host may have been blocked/deleted
		// between that query and this loop iteration.
		if host.Status != models.HostStatusEnrolled {
			continue
		}

		alert := Alert{
			HostID:             host.ID,
			HostName:           host.Name,
			NetworkID:          host.NetworkID,
			CAID:               host.CAID,
			Fingerprint:        ci.Fingerprint,
			NotAfter:           ci.NotAfter,
			SecondsUntilExpiry: ci.NotAfter.Sub(now).Seconds(),
		}

		for _, sink := range s.Sinks {
			if err := sink.Notify(ctx, alert); err != nil {
				s.logger().Error("alert sink", "host", host.ID, "error", err)
			}
		}

		if err := s.Store.RecordCertAlert(ctx, host.ID, ci.NotAfter); err != nil {
			s.logger().Error("record cert alert", "host", host.ID, "error", err)
		}
	}
	return nil
}

// StartLoop runs Scan immediately, then on every Interval tick until ctx is
// cancelled. Returns once the loop exits.
func (s *Scanner) StartLoop(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if err := s.Run(ctx); err != nil {
		s.logger().Error("initial cert-expiry scan", "error", err)
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.Run(ctx); err != nil {
				s.logger().Error("cert-expiry scan", "error", err)
			}
		}
	}
}

func (s *Scanner) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
