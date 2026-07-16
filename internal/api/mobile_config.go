package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/forgekeep/nebula-mesh/internal/mobileconfig"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func (s *Server) handleGetMobileConfig(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")
	if !s.requireMobileConfigAccess(w, r, networkID) {
		return
	}

	settings, err := loadNetworkMobileConfig(r.Context(), s.store, networkID)
	if err != nil {
		s.logger.Error("get mobile config", "network", networkID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get mobile config")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateMobileConfig(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")
	if !s.requireMobileConfigAccess(w, r, networkID) {
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	settings, err := mobileconfig.Decode(string(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		s.logger.Error("marshal mobile config", "network", networkID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update mobile config")
		return
	}
	if err := s.store.SetNetworkConfig(r.Context(), networkID, mobileconfig.StoreKey, string(settingsJSON)); err != nil {
		if errors.Is(err, store.ErrMeshImportInProgress) {
			writeError(w, http.StatusConflict, "mesh import collection is in progress for this network")
			return
		}
		s.logger.Error("set mobile config", "network", networkID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update mobile config")
		return
	}

	s.recordAuditAction(r.Context(), auditNetworkMobileConfigUpdate, networkID, string(settingsJSON))
	s.logger.Info("mobile config updated", "network", networkID)
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) requireMobileConfigAccess(w http.ResponseWriter, r *http.Request, networkID string) bool {
	network, err := s.store.GetNetwork(r.Context(), networkID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "network not found")
		return false
	}
	if err != nil {
		s.logger.Error("get network for mobile config", "network", networkID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load network")
		return false
	}
	ok, err := s.canAccessNetwork(r.Context(), network)
	if err != nil {
		s.logger.Error("mobile config authz check", "network", networkID, "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return false
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

func loadNetworkMobileConfig(ctx context.Context, s store.Store, networkID string) (mobileconfig.Settings, error) {
	raw, err := s.GetNetworkConfig(ctx, networkID, mobileconfig.StoreKey)
	if errors.Is(err, store.ErrNotFound) {
		return mobileconfig.Default(), nil
	}
	if err != nil {
		return mobileconfig.Settings{}, err
	}
	settings, err := mobileconfig.Decode(raw)
	if err != nil {
		return mobileconfig.Settings{}, fmt.Errorf("decode stored mobile config: %w", err)
	}
	return settings, nil
}
