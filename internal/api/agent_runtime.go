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
		s.logger.Error("get host for runtime report", "error", err)
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
