package api

import (
	"errors"
	"net/http"
	"time"
	"uuid"

	"github.com/go-chi/chi/v5"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type createNetworkRequest struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
	CAID  string   `json:"ca_id,omitempty"`
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
	if len(req.Name) > 255 {
		writeError(w, http.StatusBadRequest, "name must be at most 255 characters")
		return
	}
	if err := models.ValidateNetworkCIDRs(req.CIDRs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Resolve CA ID: use explicit ca_id from request, or fall back to server default CA.
	// Enforces SEC-PERSIST-001: never persist an empty ca_id. Startup invariant
	// CountEmptyCAIDRows (serve.go:134-140) rejects empty ca_id rows at restart.
	caID := req.CAID
	if caID == "" {
		caID = s.defaultCAID
	}
	if caID == "" {
		writeError(w, http.StatusBadRequest, "ca_id is required and no default CA is configured")
		return
	}

	// Validate resolved CA exists and is active (even for default CA).
	ca, err := s.store.GetCA(r.Context(), caID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	if err != nil {
		s.logger.Error("load network CA", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load CA")
		return
	}
	if ca.Status != models.CAStatusActive {
		writeError(w, http.StatusConflict, "CA must be active")
		return
	}

	network := &models.Network{
		ID:        uuid.NewV4().String(),
		Name:      req.Name,
		CIDRs:     req.CIDRs,
		CAID:      caID,
		CreatedAt: time.Now(),
	}

	if err := s.store.CreateNetwork(r.Context(), network); err != nil {
		if errors.Is(err, store.ErrMeshImportInProgress) {
			writeError(w, http.StatusConflict, "mesh import collection is in progress for this CA")
			return
		}
		s.logger.Error("create network", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create network")
		return
	}

	s.recordAuditAction(r.Context(), auditNetworkCreate, network.ID, network.Name)
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
