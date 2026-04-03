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

type createHostRequest struct {
	NetworkID string   `json:"network_id"`
	Name      string   `json:"name"`
	NebulaIP  string   `json:"nebula_ip"`
	Groups    []string `json:"groups"`
	Role      string   `json:"role"`
	PublicIP  string   `json:"public_ip,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
}

type createHostResponse struct {
	Host            *models.Host `json:"host"`
	EnrollmentToken string       `json:"enrollment_token"`
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var req createHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" || req.NebulaIP == "" || req.NetworkID == "" {
		writeError(w, http.StatusBadRequest, "name, nebula_ip, and network_id are required")
		return
	}
	if _, err := netip.ParseAddr(req.NebulaIP); err != nil {
		writeError(w, http.StatusBadRequest, "invalid nebula_ip: "+err.Error())
		return
	}

	role := models.HostRole(req.Role)
	if role == "" {
		role = models.HostRoleHost
	}

	now := time.Now()
	host := &models.Host{
		ID:           uuid.New().String(),
		NetworkID:    req.NetworkID,
		Name:         req.Name,
		NebulaIP:     req.NebulaIP,
		Groups:       req.Groups,
		Role:         role,
		IsLighthouse: role == models.HostRoleLighthouse,
		IsRelay:      role == models.HostRoleRelay,
		PublicIP:     req.PublicIP,
		ListenPort:   req.ListenPort,
		Status:       models.HostStatusPending,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if host.Groups == nil {
		host.Groups = []string{}
	}

	if err := s.store.CreateHost(r.Context(), host); err != nil {
		s.logger.Error("create host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create host")
		return
	}

	// Create enrollment token
	token := &models.EnrollmentToken{
		ID:        uuid.New().String(),
		HostID:    host.ID,
		Token:     uuid.New().String(),
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := s.store.CreateToken(r.Context(), token); err != nil {
		s.logger.Error("create token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create enrollment token")
		return
	}

	writeJSON(w, http.StatusCreated, createHostResponse{
		Host:            host,
		EnrollmentToken: token.Token,
	})
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	filter := store.HostFilter{
		NetworkID: r.URL.Query().Get("network_id"),
		Group:     r.URL.Query().Get("group"),
		Status:    models.HostStatus(r.URL.Query().Get("status")),
	}

	hosts, err := s.store.ListHosts(r.Context(), filter)
	if err != nil {
		s.logger.Error("list hosts", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list hosts")
		return
	}
	if hosts == nil {
		hosts = []*models.Host{}
	}

	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.store.GetHost(r.Context(), id)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Get host to add cert to blocklist
	host, err := s.store.GetHost(r.Context(), id)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host for delete", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	// Add to blocklist if enrolled
	if host.CertFingerprint != "" {
		if err := s.store.AddToBlocklist(r.Context(), host.CertFingerprint, host.ID, "host deleted"); err != nil {
			s.logger.Error("blocklist on delete", "error", err)
		}
	}

	if err := s.store.DeleteHost(r.Context(), id); err != nil {
		s.logger.Error("delete host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete host")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleBlockHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.store.GetHost(r.Context(), id)
	if err == store.ErrNotFound {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host for block", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	if host.CertFingerprint != "" {
		if err := s.store.AddToBlocklist(r.Context(), host.CertFingerprint, host.ID, "manually blocked"); err != nil {
			s.logger.Error("add to blocklist", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to block host")
			return
		}
	}

	host.Status = models.HostStatusBlocked
	if err := s.store.UpdateHost(r.Context(), host); err != nil {
		s.logger.Error("update host status", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update host")
		return
	}

	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleGetBlocklist(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.GetBlocklist(r.Context())
	if err != nil {
		s.logger.Error("get blocklist", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get blocklist")
		return
	}
	if list == nil {
		list = []string{}
	}

	writeJSON(w, http.StatusOK, list)
}
