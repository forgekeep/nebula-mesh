package api

import (
	"net/http"
	"strconv"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

func (s *Server) handleGetAuditLog(w http.ResponseWriter, r *http.Request) {
	filter := store.AuditFilter{
		Action: r.URL.Query().Get("action"),
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		filter.Limit, _ = strconv.Atoi(l)
	}

	entries, err := s.store.ListAuditEntries(r.Context(), filter)
	if err != nil {
		s.logger.Error("list audit entries", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get audit log")
		return
	}
	if entries == nil {
		entries = []*models.AuditEntry{}
	}

	writeJSON(w, http.StatusOK, entries)
}
