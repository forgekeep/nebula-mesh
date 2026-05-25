package api

import (
	"net/http"
	"strconv"

	"github.com/forgekeep/nebula-mesh/internal/store"
)

const defaultAuditLimit = 100

func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	if !s.isActiveAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "audit log access requires the admin role")
		return
	}
	filter := store.AuditFilter{
		Action: r.URL.Query().Get("action"),
		Limit:  defaultAuditLimit,
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid limit: must be a number")
			return
		}
		if n < 1 {
			writeError(w, http.StatusBadRequest, "invalid limit: must be positive")
			return
		}
		if n > 1000 {
			n = 1000
		}
		filter.Limit = n
	}

	entries, err := s.store.ListAuditEntries(r.Context(), filter)
	if err != nil {
		s.logger.Error("list audit entries", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get audit log")
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
