package api

import (
	"net/http"
	"time"

	"github.com/juev/nebula-mesh/internal/store"
)

type agentUpdatesResponse struct {
	HasUpdates     bool     `json:"has_updates"`
	CertificatePEM *string  `json:"certificate_pem,omitempty"`
	CACertPEM      *string  `json:"ca_certificate_pem,omitempty"`
	ConfigYAML     *string  `json:"config_yaml,omitempty"`
	Blocklist      []string `json:"blocklist"`
}

func (s *Server) handleAgentUpdates(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.URL.Query().Get("fingerprint")
	if fingerprint == "" {
		writeError(w, http.StatusBadRequest, "fingerprint query parameter is required")
		return
	}

	host, err := s.store.GetHostByFingerprint(r.Context(), fingerprint)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host by fingerprint", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	// Update last seen
	now := time.Now()
	host.LastSeenAt = &now
	if err := s.store.UpdateHost(r.Context(), host); err != nil {
		s.logger.Error("update last seen", "error", err)
	}

	// Get blocklist
	blocklist, err := s.store.GetBlocklist(r.Context())
	if err != nil {
		s.logger.Error("get blocklist", "error", err)
		blocklist = []string{}
	}

	// For now, return blocklist. Certificate and config updates
	// will be added in Phase 2 (auto-renewal).
	resp := agentUpdatesResponse{
		HasUpdates: len(blocklist) > 0,
		Blocklist:  blocklist,
	}

	writeJSON(w, http.StatusOK, resp)
}
