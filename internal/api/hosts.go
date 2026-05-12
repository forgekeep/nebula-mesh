package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
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
	if req.ListenPort < 0 || req.ListenPort > 65535 {
		writeError(w, http.StatusBadRequest, "listen_port must be between 0 and 65535")
		return
	}

	role := models.HostRole(req.Role)
	if !models.ValidRole(role) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid role: %q", req.Role))
		return
	}
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
	for _, g := range host.Groups {
		if strings.TrimSpace(g) == "" {
			writeError(w, http.StatusBadRequest, "group names must not be empty")
			return
		}
	}

	token := &models.EnrollmentToken{
		ID:        uuid.New().String(),
		HostID:    host.ID,
		Token:     uuid.New().String(),
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := s.store.CreateHostAndToken(r.Context(), host, token); err != nil {
		s.logger.Error("create host and token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create host")
		return
	}
	_ = s.store.AddAuditEntry(r.Context(), ActorName(r.Context()), "host.create", host.ID, host.Name)

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
		Limit:     1000,
	}

	hosts, err := s.store.ListHosts(r.Context(), filter)
	if err != nil {
		s.logger.Error("list hosts", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list hosts")
		return
	}
	writeJSON(w, http.StatusOK, hosts)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
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
	if err := s.store.DeleteHostAndBlockCert(r.Context(), id, "host deleted"); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "host not found")
			return
		}
		s.logger.Error("delete host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete host")
		return
	}
	_ = s.store.AddAuditEntry(r.Context(), ActorName(r.Context()), "host.delete", id, "")

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleBlockHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.store.BlockHostAndAddToBlocklist(r.Context(), id, "manually blocked")
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("block host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to block host")
		return
	}
	_ = s.store.AddAuditEntry(r.Context(), ActorName(r.Context()), "host.block", id, "")

	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleUnblockHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.store.UnblockHostAndRemoveFromBlocklist(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("unblock host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to unblock host")
		return
	}
	_ = s.store.AddAuditEntry(r.Context(), ActorName(r.Context()), "host.unblock", id, "")

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
