package api

import (
	"context"
	"encoding/json"
	"expvar"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/juev/nebula-mesh/internal/configgen"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

// CAConfig holds paths and passphrase for CA persistence.
type CAConfig struct {
	CertPath   string
	KeyPath    string
	Passphrase string
}

// Server is the HTTP API server.
type Server struct {
	router      chi.Router
	store       store.Store
	caMu        sync.RWMutex
	ca          *pki.CAManager  // legacy single-CA fallback when host.CAID is empty
	caResolver  *pki.CAResolver // resolves CAs by id from the store (multi-CA)
	master      *keystore.Master
	defaultCAID string // id of the seeded default CA (when imported)
	caConfig    CAConfig
	logger      *slog.Logger
	apiKey      string
}

// NewServer creates a new API server.
func NewServer(s store.Store, ca *pki.CAManager, apiKey string, logger *slog.Logger, caCfg CAConfig) *Server {
	srv := &Server{
		store:    s,
		ca:       ca,
		caConfig: caCfg,
		logger:   logger,
		apiKey:   apiKey,
	}
	srv.setupRoutes()
	return srv
}

// WithCAResolver attaches a CAResolver. Must be called before ServeHTTP.
// When set, host signing operations look up the CA by host.CAID; the
// legacy single-CA fallback is used only when host.CAID is empty.
func (s *Server) WithCAResolver(r *pki.CAResolver) {
	s.caResolver = r
}

// WithMaster sets the master keystore used to create new CAs.
func (s *Server) WithMaster(m *keystore.Master) { s.master = m }

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
	r.Use(maxBodySize(1 << 20)) // 1MB

	// Public endpoints — operations and enrollment
	r.Get("/health", s.handleHealth) // legacy alias
	r.Get("/healthz", s.handleHealth)
	r.Get("/readyz", s.handleReady)
	r.Method("GET", "/metrics", expvar.Handler())
	r.Post("/api/v1/enroll", s.handleEnroll)
	r.Get("/api/v1/agent/updates", s.handleAgentUpdates)

	// Protected endpoints (require API key)
	r.Group(func(r chi.Router) {
		r.Use(bearerAuth(s.store, s.apiKey))
		r.Post("/api/v1/networks", s.handleCreateNetwork)
		r.Get("/api/v1/networks", s.handleListNetworks)
		r.Get("/api/v1/networks/{id}", s.handleGetNetwork)
		r.Post("/api/v1/hosts", s.handleCreateHost)
		r.Get("/api/v1/hosts", s.handleListHosts)
		r.Get("/api/v1/hosts/{id}", s.handleGetHost)
		r.Delete("/api/v1/hosts/{id}", s.handleDeleteHost)
		r.Post("/api/v1/hosts/{id}/block", s.handleBlockHost)
		r.Post("/api/v1/hosts/{id}/unblock", s.handleUnblockHost)
		r.Get("/api/v1/blocklist", s.handleGetBlocklist)
		r.Get("/api/v1/ca", s.handleGetCA)
		r.Post("/api/v1/ca/rotate", s.handleRotateCA)
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
