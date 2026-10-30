package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// handleAgentRuntime records the Nebula version and OS a host's agent runs
// (#400). Both values travel in the path because the PoP signature covers the
// path but not the body or query; see pop.CanonicalString.
func (s *Server) handleAgentRuntime(w http.ResponseWriter, r *http.Request) {
	goos := chi.URLParam(r, "os")
	if !nebulacompat.ValidAgentOS(goos) {
		writeError(w, http.StatusBadRequest, "invalid_os")
		return
	}
	version, err := nebulacompat.ParseVersion(chi.URLParam(r, "version"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_nebula_version")
		return
	}
	host, ok := s.authenticateAgentReport(w, r)
	if !ok {
		return
	}
	changed, err := s.store.ReportHostNebulaRuntime(r.Context(), host.ID, version.String(), goos, time.Now().UTC())
	if err != nil {
		s.logger.Error("record host nebula runtime", "host", host.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "runtime_report_failed")
		return
	}
	if changed {
		s.recordAuditAction(r.Context(), auditHostNebulaRuntimeChanged, host.ID,
			"nebula_version="+version.String()+" os="+goos)
	}
	writeJSON(w, http.StatusOK, map[string]string{"nebula_version": version.String(), "os": goos})
}

// handleAgentRestartPending records whether a delivered config still waits for
// a Nebula restart (#400). The state travels in the signed path.
func (s *Server) handleAgentRestartPending(w http.ResponseWriter, r *http.Request) {
	var pending bool
	switch chi.URLParam(r, "state") {
	case "required":
		pending = true
	case "cleared":
	default:
		writeError(w, http.StatusBadRequest, "invalid_restart_state")
		return
	}
	host, ok := s.authenticateAgentReport(w, r)
	if !ok {
		return
	}
	changed, err := s.store.SetHostNebulaRestartPending(r.Context(), host.ID, pending, time.Now().UTC())
	if err != nil {
		s.logger.Error("record host restart pending", "host", host.ID, "error", err)
		writeError(w, http.StatusInternalServerError, "restart_report_failed")
		return
	}
	if changed {
		s.recordAuditAction(r.Context(), auditHostNebulaRestartPending, host.ID, "state="+chi.URLParam(r, "state"))
	}
	writeJSON(w, http.StatusOK, map[string]bool{"restart_pending": pending})
}

// authenticateAgentReport applies the signed-poll proof to an agent report and
// admits only hosts that may still report. On failure it writes the response.
func (s *Server) authenticateAgentReport(w http.ResponseWriter, r *http.Request) (*models.Host, bool) {
	headers, ok := readAgentAuthHeaders(w, r)
	if !ok {
		return nil, false
	}
	host, err := s.store.GetHostByFingerprint(r.Context(), headers.fingerprint)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "unknown_fingerprint")
		return nil, false
	}
	if err != nil {
		s.logger.Error("get host for agent report", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to authenticate host")
		return nil, false
	}
	if !s.authenticateKnownAgentRequest(w, r, host, headers) {
		return nil, false
	}
	if host.Status == models.HostStatusBlocked {
		writeError(w, http.StatusForbidden, "host_revoked")
		return nil, false
	}
	if host.Status != models.HostStatusEnrolled && host.Status != models.HostStatusPending {
		writeError(w, http.StatusConflict, "host_not_enrolled")
		return nil, false
	}
	return host, true
}
