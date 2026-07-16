package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func (s *Server) handleAgentConfigAck(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.Atoi(chi.URLParam(r, "version"))
	if err != nil || version <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_config_version")
		return
	}
	headers, ok := readAgentAuthHeaders(w, r)
	if !ok {
		return
	}
	host, err := s.store.GetHostByFingerprint(r.Context(), headers.fingerprint)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "unknown_fingerprint")
		return
	}
	if err != nil {
		s.logger.Error("get host for config ack", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to authenticate host")
		return
	}
	if !s.authenticateKnownAgentRequest(w, r, host, headers) {
		return
	}
	if host.Status == models.HostStatusBlocked {
		writeError(w, http.StatusForbidden, "host_revoked")
		return
	}
	if host.Status != models.HostStatusEnrolled && host.Status != models.HostStatusPending {
		writeError(w, http.StatusConflict, "host_not_enrolled")
		return
	}
	if err := s.store.AcknowledgeHostConfigVersion(r.Context(), host.ID, version); err != nil {
		switch {
		case errors.Is(err, store.ErrConfigVersionMismatch), errors.Is(err, store.ErrConfigAckUnsupported):
			writeError(w, http.StatusConflict, "config_ack_conflict")
		case errors.Is(err, store.ErrHostNotEnrolled):
			writeError(w, http.StatusConflict, "host_not_enrolled")
		default:
			s.logger.Error("ack host config version", "host", host.ID, "error", err)
			writeError(w, http.StatusInternalServerError, "config_ack_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"config_version": version})
}
