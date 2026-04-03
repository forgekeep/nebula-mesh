package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/juev/nebula-mgmt/internal/configgen"
	"github.com/juev/nebula-mgmt/internal/pki"
	"github.com/juev/nebula-mgmt/internal/store"
)

// CAConfig holds paths and passphrase for CA persistence.
type CAConfig struct {
	CertPath   string
	KeyPath    string
	Passphrase string
}

// Server is the HTTP API server.
type Server struct {
	router   chi.Router
	store    store.Store
	caMu     sync.RWMutex
	ca       *pki.CAManager
	caConfig CAConfig
	logger   *slog.Logger
	apiKey   string
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

func (s *Server) setupRoutes() {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger(s.logger))
	r.Use(maxBodySize(1 << 20)) // 1MB

	// Public endpoints
	r.Get("/health", s.handleHealth)
	r.Post("/api/v1/enroll", s.handleEnroll)
	r.Get("/api/v1/agent/updates", s.handleAgentUpdates)

	// Protected endpoints (require API key)
	r.Group(func(r chi.Router) {
		r.Use(bearerAuth(s.apiKey))
		r.Post("/api/v1/networks", s.handleCreateNetwork)
		r.Get("/api/v1/networks", s.handleListNetworks)
		r.Get("/api/v1/networks/{id}", s.handleGetNetwork)
		r.Post("/api/v1/hosts", s.handleCreateHost)
		r.Get("/api/v1/hosts", s.handleListHosts)
		r.Get("/api/v1/hosts/{id}", s.handleGetHost)
		r.Delete("/api/v1/hosts/{id}", s.handleDeleteHost)
		r.Post("/api/v1/hosts/{id}/block", s.handleBlockHost)
		r.Get("/api/v1/blocklist", s.handleGetBlocklist)
		r.Get("/api/v1/ca", s.handleGetCA)
		r.Post("/api/v1/ca/rotate", s.handleRotateCA)
		r.Get("/api/v1/networks/{id}/firewall", s.handleGetFirewall)
		r.Put("/api/v1/networks/{id}/firewall", s.handleUpdateFirewall)
		r.Get("/api/v1/audit-log", s.handleGetAuditLog)
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
