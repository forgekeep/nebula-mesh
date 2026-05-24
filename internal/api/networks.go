package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

type createNetworkRequest struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	if !s.isActiveAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "network creation requires the admin role")
		return
	}
	var req createNetworkRequest
	if err := decodeJSONStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := models.ValidateNetworkCIDRs(req.CIDRs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	network := &models.Network{
		ID:        uuid.New().String(),
		Name:      req.Name,
		CIDRs:     req.CIDRs,
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
	if !s.isActiveAdmin(r.Context()) {
		actor := ActorOf(r.Context())
		if actor == nil {
			writeJSON(w, http.StatusOK, []*models.Network{})
			return
		}
		cas, err := s.store.ListCAsByOwner(r.Context(), actor.ID)
		if err != nil {
			s.logger.Error("list cas by owner", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to scope networks")
			return
		}
		owned := make(map[string]struct{}, len(cas))
		for _, ca := range cas {
			owned[ca.ID] = struct{}{}
		}
		filtered := networks[:0]
		for _, n := range networks {
			if _, ok := owned[n.CAID]; ok {
				filtered = append(filtered, n)
			}
		}
		networks = filtered
	}
	writeJSON(w, http.StatusOK, networks)
}

func (s *Server) handleGetNetwork(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	network, err := s.store.GetNetwork(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	if err != nil {
		s.logger.Error("get network", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get network")
		return
	}
	ok, err := s.canAccessNetwork(r.Context(), network)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	writeJSON(w, http.StatusOK, network)
}
