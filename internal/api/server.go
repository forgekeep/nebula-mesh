package api

import (
	"context"
	"encoding/json"
	"expvar"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/forgekeep/nebula-mesh/internal/auth"
	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/ratelimit"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// Server is the HTTP API server.
type Server struct {
	router             chi.Router
	store              store.Store
	caResolver         *pki.CAResolver // resolves CAs by id from the store (multi-CA)
	master             *keystore.Master
	defaultCAID        string // id of the seeded default CA (when imported)
	logger             *slog.Logger
	metrics            *metrics
	metricsEnabled     bool
	hostSeen           HostSeenEmitter
	limiter            *ratelimit.Limiter
	passwordPolicy     auth.Policy
	enrollmentTokenTTL time.Duration
}

// NewServer creates a new API server.
func NewServer(s store.Store, logger *slog.Logger) *Server {
	srv := &Server{
		store:              s,
		logger:             logger,
		metrics:            newMetrics(s),
		metricsEnabled:     true,
		passwordPolicy:     auth.Default(),
		enrollmentTokenTTL: 24 * time.Hour,
	}
	srv.setupRoutes()
	return srv
}

// WithEnrollmentTokenTTL sets the default enrollment-token TTL applied when
// the per-network override is unset. Default is 24h (ADR 0004 §7.1).
func (s *Server) WithEnrollmentTokenTTL(ttl time.Duration) {
	if ttl > 0 {
		s.enrollmentTokenTTL = ttl
	}
}

// tokenTTLFor resolves the enrollment-token TTL for the network. Order of
// precedence: per-network `enrollment_token_ttl` value in `network_config`,
// then the server-level default, then 24h.
func (s *Server) tokenTTLFor(ctx context.Context, networkID string) time.Duration {
	if networkID != "" {
		v, err := s.store.GetNetworkConfig(ctx, networkID, "enrollment_token_ttl")
		if err == nil && v != "" {
			if d, perr := time.ParseDuration(v); perr == nil && d > 0 {
				return d
			}
		}
	}
	if s.enrollmentTokenTTL > 0 {
		return s.enrollmentTokenTTL
	}
	return 24 * time.Hour
}

// WithCAResolver attaches a CAResolver. Must be called before ServeHTTP.
// When set, host signing operations look up the CA by host.CAID; the
// legacy single-CA fallback is used only when host.CAID is empty.
func (s *Server) WithCAResolver(r *pki.CAResolver) {
	s.caResolver = r
}

// WithMaster sets the master keystore used to create new CAs.
func (s *Server) WithMaster(m *keystore.Master) { s.master = m }

// RecordLogin records an operator login attempt against the server's
// Prometheus metrics. Exposed so the Web UI handlers (a separate package)
// can plumb their login outcomes through without an import cycle.
//
// Result is one of "ok" / "denied" / "error"; factor is one of
// "password" / "totp" / "recovery" / "oidc".
func (s *Server) RecordLogin(result, factor string) {
	s.metrics.recordLogin(result, factor)
}

// WithRateLimiter installs a rate-limit middleware. nil disables limiting.
func (s *Server) WithRateLimiter(l *ratelimit.Limiter) {
	s.limiter = l
	s.setupRoutes()
}

// WithPasswordPolicy installs the policy applied to every server-side
// password-setting path (operator create, future operator reset).
func (s *Server) WithPasswordPolicy(p auth.Policy) { s.passwordPolicy = p }

// WithMetricsEnabled toggles the Prometheus /metrics endpoint. Disable in
// air-gapped deployments where the exporter is not scraped. Must be called
// before the router is exercised by ServeHTTP — re-wires the routes.
func (s *Server) WithMetricsEnabled(enabled bool) {
	s.metricsEnabled = enabled
	s.setupRoutes()
}

// HostSeenEmitter is invoked after every successful agent poll so the Web
// UI can stream a live "host X just polled" event over its SSE endpoint.
// hostID is the DB id, lastSeen is the wall-clock timestamp the agent's
// poll was observed at, and networkID is included so per-network views can
// filter without an extra lookup.
type HostSeenEmitter func(hostID string, lastSeen time.Time, networkID string)

// WithHostSeenEmitter wires the callback the API server fires when an
// agent polls. Passing nil disables emission.
func (s *Server) WithHostSeenEmitter(emit HostSeenEmitter) {
	s.hostSeen = emit
}

// WithDefaultCAID records the id of the CA seeded from the legacy
// on-disk material. Used when host.CAID matches this id to short-circuit
// to the legacy in-memory CAManager.
func (s *Server) WithDefaultCAID(id string) {
	s.defaultCAID = id
}

func (s *Server) setupRoutes() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger(s.logger))
	r.Use(s.metricsMiddleware())
	r.Use(maxBodySize(1 << 20)) // 1MB

	// Public endpoints — operations and enrollment
	r.Get("/health", s.handleHealth) // legacy alias
	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)
	if s.metricsEnabled {
		r.Method("GET", "/metrics", promhttp.HandlerFor(s.metrics.reg, promhttp.HandlerOpts{}))
	}
	r.Method("GET", "/debug/vars", expvar.Handler())
	r.Group(func(r chi.Router) {
		r.Use(s.rateLimitMiddleware("enroll"))
		r.Post("/api/v1/enroll", s.handleEnroll)
	})
	r.Group(func(r chi.Router) {
		r.Use(s.rateLimitMiddleware("agent_poll"))
		r.Get("/api/v1/agent/updates", s.handleAgentUpdates)
	})

	// Protected endpoints (require API key)
	r.Group(func(r chi.Router) {
		r.Use(s.rateLimitMiddleware("api"))
		r.Use(bearerAuth(s.store))
		r.Post("/api/v1/networks", s.handleCreateNetwork)
		r.Get("/api/v1/networks", s.handleListNetworks)
		r.Get("/api/v1/networks/{id}", s.handleGetNetwork)
		r.Post("/api/v1/hosts", s.handleCreateHost)
		r.Get("/api/v1/hosts", s.handleListHosts)
		r.Get("/api/v1/hosts/{id}", s.handleGetHost)
		r.Patch("/api/v1/hosts/{id}", s.handleUpdateHost)
		r.Delete("/api/v1/hosts/{id}", s.handleDeleteHost)
		r.Post("/api/v1/hosts/{id}/block", s.handleBlockHost)
		r.Post("/api/v1/hosts/{id}/unblock", s.handleUnblockHost)
		r.Post("/api/v1/hosts/{id}/enrollment-token", s.handleRegenerateEnrollmentToken)
		r.Post("/api/v1/hosts/{id}/rotate-cert", s.handleRotateCert)
		r.Post("/api/v1/hosts/{id}/reenroll", s.handleReenroll)
		r.Post("/api/v1/hosts/{id}/mobile-bundle", s.handleMobileBundle)
		r.Get("/api/v1/blocklist", s.handleGetBlocklist)
		r.Get("/api/v1/networks/{id}/firewall", s.handleGetFirewall)
		r.Put("/api/v1/networks/{id}/firewall", s.handleUpdateFirewall)
		r.Get("/api/v1/audit-log", s.handleGetAuditLog)
		r.Get("/api/v1/operators", s.handleListOperators)
		r.Post("/api/v1/operators", s.handleCreateOperator)
		r.Post("/api/v1/operators/{id}/disable", s.handleDisableOperator)
		r.Post("/api/v1/operators/{id}/enable", s.handleEnableOperator)
		r.Get("/api/v1/operators/{id}/api-keys", s.handleListOperatorAPIKeys)
		r.Post("/api/v1/operators/{id}/api-keys", s.handleCreateOperatorAPIKey)
		r.Delete("/api/v1/operators/{id}/api-keys/{kid}", s.handleRevokeOperatorAPIKey)
		r.Get("/api/v1/cas", s.handleListCAs)
		r.Post("/api/v1/cas", s.handleCreateCA)
		r.Get("/api/v1/cas/{id}", s.handleGetCAByID)
		r.Delete("/api/v1/cas/{id}", s.handleDeleteCA)
		r.Post("/api/v1/cas/{id}/rotate", s.handleRotateCA)
		r.Get("/api/v1/settings", s.handleGetSettings)
		r.Patch("/api/v1/settings", s.handlePatchSettings)
	})

	s.router = r
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady reports readiness — verifies the database is reachable.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// writeJSON sends a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode JSON response", "error", err)
	}
}

// writeError sends a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// ConfigGenerator is used by handlers to generate Nebula configs.
// Kept separate to avoid circular deps.
var _ = configgen.GeneratorInput{} // compile-time check that configgen is importable

// contextWithTimeout wraps context.WithTimeout for tests that may pass a nil request context.
func contextWithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, d)
}
