package api

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

type createNetworkRequest struct {
	Name string `json:"name"`
	CIDR string `json:"cidr"`
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req createNetworkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.CIDR == "" {
		writeError(w, http.StatusBadRequest, "name and cidr are required")
		return
	}
	if _, err := netip.ParsePrefix(req.CIDR); err != nil {
		writeError(w, http.StatusBadRequest, "invalid CIDR: "+err.Error())
		return
	}

	network := &models.Network{
		ID:        uuid.New().String(),
		Name:      req.Name,
		CIDR:      req.CIDR,
		CreatedAt: time.Now(),
	}

	if err := s.store.CreateNetwork(r.Context(), network); err != nil {
		s.logger.Error("create network", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create network")
		return
	}

	writeJSON(w, http.StatusCreated, network)
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := s.store.ListNetworks(r.Context())
	if err != nil {
		s.logger.Error("list networks", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list networks")
		return
	}
	if networks == nil {
		networks = []*models.Network{}
	}

	writeJSON(w, http.StatusOK, networks)
}

func (s *Server) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	network, err := s.store.GetNetwork(r.Context(), id)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	if err != nil {
		s.logger.Error("get network", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get network")
		return
	}

	writeJSON(w, http.StatusOK, network)
}
