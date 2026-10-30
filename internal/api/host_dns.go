package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/hostdns"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// handleGetHostDNS returns the network's split DNS setting for Nebula's
// experimental `dns` stanza (#400).
func (s *Server) handleGetHostDNS(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")
	if !s.requireNetworkConfigAccess(w, r, networkID) {
		return
	}
	settings, err := loadNetworkHostDNS(r.Context(), s.store, networkID)
	if err != nil {
		s.logger.Error("get host dns", "network", networkID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host dns")
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateHostDNS(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")
	if !s.requireNetworkConfigAccess(w, r, networkID) {
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	settings, err := hostdns.Decode(string(body))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		s.logger.Error("marshal host dns", "network", networkID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update host dns")
		return
	}
	// Unlike mobile-config, the stanza is rendered into agent configs, so the
	// network version moves and every host gets its config again.
	if err := s.store.SetNetworkConfigAndBumpVersion(r.Context(), networkID, hostdns.StoreKey, string(settingsJSON)); err != nil {
		if errors.Is(err, store.ErrMeshImportInProgress) {
			writeError(w, http.StatusConflict, "mesh import collection is in progress for this network")
			return
		}
		s.logger.Error("set host dns", "network", networkID, "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update host dns")
		return
	}
	s.recordAuditAction(r.Context(), auditNetworkHostDNSUpdate, networkID, string(settingsJSON))
	s.logger.Info("host dns updated", "network", networkID)
	writeJSON(w, http.StatusOK, settings)
}

func loadNetworkHostDNS(ctx context.Context, s store.Store, networkID string) (hostdns.Settings, error) {
	raw, err := s.GetNetworkConfig(ctx, networkID, hostdns.StoreKey)
	if errors.Is(err, store.ErrNotFound) {
		return hostdns.Default(), nil
	}
	if err != nil {
		return hostdns.Settings{}, err
	}
	settings, err := hostdns.Decode(raw)
	if err != nil {
		return hostdns.Settings{}, fmt.Errorf("decode stored host dns: %w", err)
	}
	return settings, nil
}

// generatorHostDNS converts the stored setting for the renderer; nil when
// the stanza is off.
func generatorHostDNS(settings hostdns.Settings) *configgen.HostDNS {
	if !settings.Enabled() {
		return nil
	}
	return &configgen.HostDNS{
		Nameservers:   settings.Nameservers,
		MatchDomains:  settings.MatchDomains,
		SearchDomains: settings.SearchDomains,
	}
}
