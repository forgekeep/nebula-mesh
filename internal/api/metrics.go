package api

import (
	"context"
	"math"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

// Result labels for counters whose terminal outcome falls into one of three
// buckets (request succeeded / was refused / failed unexpectedly). Used by
// enrollments, cert renewals, and operator logins. Exported so the Web UI
// package can use the same constants when reporting login outcomes back to
// the API server via RecordLogin.
const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	ResultError  = "error"
)

// Authentication factor labels for nebula_mgmt_operator_logins_total.
const (
	LoginFactorPassword = "password"
	LoginFactorTOTP     = "totp"
	LoginFactorRecovery = "recovery"
	LoginFactorOIDC     = "oidc"
)

// resultOK / resultDenied / resultError remain as package-local aliases so
// existing internal callers (enrollments, cert renewals) keep their concise
// names without having to switch to the exported spelling everywhere.
const (
	resultOK     = ResultOK
	resultDenied = ResultDenied
	resultError  = ResultError
)

const (
	loginFactorPassword = LoginFactorPassword
	loginFactorTOTP     = LoginFactorTOTP
	loginFactorRecovery = LoginFactorRecovery
	loginFactorOIDC     = LoginFactorOIDC
)

// Audit action labels: stable identifiers for the audit log entries the API
// writes. Centralized here so the Prometheus counter, the audit log, and any
// future RBAC tooling can share the same vocabulary instead of duplicating
// string literals.
const (
	auditHostCreate                = "host.create"
	auditHostDelete                = "host.delete"
	auditHostUpdate                = "host.update"
	auditHostBlock                 = "host.block"
	auditHostUnblock               = "host.unblock"
	auditHostAuthFailed            = "host.auth.failed"
	auditHostRotateCertRequested   = "host.rotate-cert.requested"
	auditHostReenrollRequested     = "host.reenroll.requested"
	auditHostRekeyCompleted        = "host.rekey.completed"
	auditHostMobileBundleIssued    = "host.mobile_bundle.issued"
	auditHostMobileBundleForbidden = "host.mobile_bundle.forbidden"
	auditCACreated                 = "ca.created"
	auditCADeleted                 = "ca.deleted"
	auditCARotated                 = "ca.rotated"
	auditNetworkCreate             = "network.create"
	auditNetworkFirewallUpdate     = "network.firewall.update"
	auditOperatorCreate            = "operator.create"
	auditOperatorDisable           = "operator.disable"
	auditOperatorEnable            = "operator.enable"
	auditOperatorAPIKeyCreate      = "operator.api_key.create"
	auditOperatorAPIKeyRevoke      = "operator.api_key.revoke"
	auditSettingsEnforce2FA        = "settings.enforce_2fa"
)

// Audit reason codes used in the `details` field of host.auth.failed audit
// entries (ADR 0004 §8 — telemetry). Surfaced as constants so server-side and
// test code share one source of truth.
const (
	authReasonUnknownFingerprint = "unknown_fingerprint"
	authReasonBadSignature       = "bad_signature"
	authReasonTimestampSkew      = "timestamp_skew"
	authReasonReplayedNonce      = "replayed_nonce"
	authReasonRevoked            = "revoked"
	authReasonGone               = "gone"
)

// caIDFallback is the label value used when a CA signing event happens on
// the legacy single-CA fallback path (no per-host CAID is recorded).
const caIDFallback = "default"

// hostStatusNone is the label value emitted by the hosts gauge when there are
// no enrolled hosts at all — gives dashboards a stable schema to bind to.
const hostStatusNone = "none"

// metrics holds the Prometheus registry and every application metric exposed
// at /metrics. The registry is private to the server instance so test runs
// don't fight over Prometheus's default registerer global state.
type metrics struct {
	reg            *prometheus.Registry
	httpRequests   *prometheus.CounterVec
	httpDuration   *prometheus.HistogramVec
	enrollments    *prometheus.CounterVec
	certRenewals   *prometheus.CounterVec
	auditEntries   *prometheus.CounterVec
	operatorLogins *prometheus.CounterVec
	caSignatures   *prometheus.CounterVec
}

// newMetrics builds a fresh metrics bundle bound to an isolated registry and
// pre-registers the application counters / histograms / collectors. Gauges
// derived from the store (host counts, soonest cert expiry) are exposed via
// a dedicated storeCollector so they always reflect the live state on scrape.
func newMetrics(s store.Store) *metrics {
	reg := prometheus.NewRegistry()
	m := &metrics{
		reg: reg,
		httpRequests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nebula_mgmt_http_requests_total",
				Help: "Total number of HTTP requests served by the management API.",
			},
			[]string{"method", "route", "status"},
		),
		httpDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "nebula_mgmt_http_request_duration_seconds",
				Help:    "Server-side latency for HTTP requests, in seconds.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "route"},
		),
		enrollments: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nebula_mgmt_enrollments_total",
				Help: "Enrollment attempts grouped by terminal result.",
			},
			[]string{"result"},
		),
		certRenewals: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nebula_mgmt_cert_renewals_total",
				Help: "Auto certificate-renewal attempts grouped by terminal result.",
			},
			[]string{"result"},
		),
		auditEntries: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nebula_mgmt_audit_entries_total",
				Help: "Audit log entries written, grouped by action.",
			},
			[]string{"action"},
		),
		operatorLogins: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nebula_mgmt_operator_logins_total",
				Help: "Operator login attempts grouped by terminal result and factor.",
			},
			[]string{"result", "factor"},
		),
		caSignatures: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "nebula_mgmt_ca_signatures_total",
				Help: "Successful certificate signings, grouped by signing CA id.",
			},
			[]string{"ca_id"},
		),
	}

	reg.MustRegister(m.httpRequests)
	reg.MustRegister(m.httpDuration)
	reg.MustRegister(m.enrollments)
	reg.MustRegister(m.certRenewals)
	reg.MustRegister(m.auditEntries)
	reg.MustRegister(m.operatorLogins)
	reg.MustRegister(m.caSignatures)

	// Pre-seed canonical label combinations with zero so every metric shows
	// up in the exposition output even before the first event, giving
	// dashboards a stable schema and alerts something to threshold on.
	results := []string{resultOK, resultDenied, resultError}
	for _, result := range results {
		m.enrollments.WithLabelValues(result).Add(0)
		m.certRenewals.WithLabelValues(result).Add(0)
	}
	for _, factor := range []string{loginFactorPassword, loginFactorTOTP, loginFactorRecovery, loginFactorOIDC} {
		for _, result := range results {
			m.operatorLogins.WithLabelValues(result, factor).Add(0)
		}
	}
	m.caSignatures.WithLabelValues(caIDFallback).Add(0)
	for _, action := range []string{
		auditHostCreate, auditHostDelete, auditHostUpdate, auditHostBlock, auditHostUnblock,
		auditCACreated, auditCADeleted, auditCARotated,
		auditNetworkCreate, auditNetworkFirewallUpdate,
		auditOperatorCreate, auditOperatorDisable, auditOperatorEnable,
		auditOperatorAPIKeyCreate, auditOperatorAPIKeyRevoke,
		auditSettingsEnforce2FA,
	} {
		m.auditEntries.WithLabelValues(action).Add(0)
	}

	reg.MustRegister(newStoreCollector(s))
	return m
}

// recordEnrollment bumps the enrollments counter. Result is one of
// "ok" / "denied" / "error" — matching the labels documented in the README.
func (m *metrics) recordEnrollment(result string) {
	if m == nil {
		return
	}
	m.enrollments.WithLabelValues(result).Inc()
}

func (m *metrics) recordRenewal(result string) {
	if m == nil {
		return
	}
	m.certRenewals.WithLabelValues(result).Inc()
}

func (m *metrics) recordAudit(action string) {
	if m == nil {
		return
	}
	m.auditEntries.WithLabelValues(action).Inc()
}

func (m *metrics) recordLogin(result, factor string) {
	if m == nil {
		return
	}
	m.operatorLogins.WithLabelValues(result, factor).Inc()
}

func (m *metrics) recordSignature(caID string) {
	if m == nil {
		return
	}
	if caID == "" {
		caID = caIDFallback
	}
	m.caSignatures.WithLabelValues(caID).Inc()
}

// --- storeCollector -------------------------------------------------------

// storeCollector exposes gauges whose values depend on the current DB state:
//
//   - nebula_mgmt_hosts{status, network} — total hosts grouped by status and
//     network id.
//   - nebula_mgmt_certificates_expiring_seconds — wall-clock seconds until
//     the soonest-to-expire enrolled certificate. Negative values indicate the
//     soonest cert has already expired. Reports +Inf when no certs exist.
//
// The collector is queried on every Prometheus scrape, so the work is bounded
// by the scrape cadence (typically 15-60s) and the host/cert table sizes.
type storeCollector struct {
	store   store.Store
	hosts   *prometheus.Desc
	exp     *prometheus.Desc
	perHost *prometheus.Desc
}

func newStoreCollector(s store.Store) *storeCollector {
	return &storeCollector{
		store: s,
		hosts: prometheus.NewDesc(
			"nebula_mgmt_hosts",
			"Total hosts grouped by status and network.",
			[]string{"status", "network"}, nil,
		),
		exp: prometheus.NewDesc(
			"nebula_mgmt_certificates_expiring_seconds",
			"Seconds remaining until the soonest-to-expire enrolled certificate.",
			nil, nil,
		),
		perHost: prometheus.NewDesc(
			"nebula_mgmt_cert_expiring_seconds",
			"Seconds remaining until the current certificate of each enrolled host expires.",
			[]string{"host", "network"}, nil,
		),
	}
}

func (c *storeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.hosts
	ch <- c.exp
	ch <- c.perHost
}

func (c *storeCollector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()

	// Hosts gauge: count by (status, network). Always emit at least one
	// sample so the metric is visible in the exposition format even when
	// no hosts are registered yet (gives dashboards a stable schema).
	type key struct{ status, network string }
	counts := map[key]float64{{status: hostStatusNone, network: ""}: 0}
	if hosts, err := c.store.ListHosts(ctx, store.HostFilter{}); err == nil {
		for _, h := range hosts {
			counts[key{string(h.Status), h.NetworkID}]++
		}
	}
	for k, n := range counts {
		ch <- prometheus.MustNewConstMetric(c.hosts, prometheus.GaugeValue, n, k.status, k.network)
	}

	// Soonest-cert-expiry gauge: wall-clock seconds remaining until the
	// soonest-to-expire enrolled certificate. Negative values mean the cert
	// has already expired. Reports +Inf when no certs exist so absence is
	// distinguishable from "expiring now". Also emits a per-host
	// nebula_mgmt_cert_expiring_seconds{host, network} so alerting rules
	// can target individual hosts (see issue #41 Prometheus sink).
	seconds := math.Inf(1)
	if certs, err := c.store.ListEnrolledHostCerts(ctx); err == nil {
		hostNetwork := map[string]string{}
		if hosts, herr := c.store.ListHosts(ctx, store.HostFilter{}); herr == nil {
			for _, h := range hosts {
				hostNetwork[h.ID] = h.NetworkID
			}
		}

		soonest := time.Time{}
		for _, ci := range certs {
			remaining := time.Until(ci.NotAfter).Seconds()
			ch <- prometheus.MustNewConstMetric(
				c.perHost, prometheus.GaugeValue, remaining,
				ci.HostID, hostNetwork[ci.HostID],
			)
			if soonest.IsZero() || ci.NotAfter.Before(soonest) {
				soonest = ci.NotAfter
			}
		}
		if !soonest.IsZero() {
			seconds = time.Until(soonest).Seconds()
		}
	}
	ch <- prometheus.MustNewConstMetric(c.exp, prometheus.GaugeValue, seconds)
}
