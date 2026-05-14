package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
)

type createHostRequest struct {
	NetworkID  string               `json:"network_id"`
	Name       string               `json:"name"`
	NebulaIP   string               `json:"nebula_ip"`
	Groups     []string             `json:"groups"`
	Role       string               `json:"role"`
	PublicIP   string               `json:"public_ip,omitempty"`
	ListenPort int                  `json:"listen_port,omitempty"`
	Advanced   *models.HostAdvanced `json:"advanced,omitempty"`
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
	if err := validateHostIP(r.Context(), s.store, req.NetworkID, req.NebulaIP, ""); err != nil {
		if IsHostIPValidationError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("validate host ip", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to validate nebula_ip")
		return
	}
	if req.ListenPort < 0 || req.ListenPort > 65535 {
		writeError(w, http.StatusBadRequest, "listen_port must be between 0 and 65535")
		return
	}

	if strings.TrimSpace(req.PublicIP) != "" {
		if _, err := models.ValidateIPAddr("public_ip", req.PublicIP); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	role := models.HostRole(req.Role)
	if !models.ValidRole(role) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid role: %q", req.Role))
		return
	}
	if role == "" {
		role = models.HostRoleHost
	}
	if err := models.ValidateRoleReachability(role, req.PublicIP, req.ListenPort); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := validateHostAdvanced(req.Advanced); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
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
		Advanced:     req.Advanced,
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
		ExpiresAt: now.Add(s.tokenTTLFor(r.Context(), host.NetworkID)),
		CreatedAt: now,
	}
	if err := s.store.CreateHostAndToken(r.Context(), host, token); err != nil {
		s.logger.Error("create host and token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create host")
		return
	}
	s.recordAuditAction(r.Context(), auditHostCreate, host.ID, host.Name)

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
	s.recordAuditAction(r.Context(), auditHostDelete, id, "")

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
	s.recordAuditAction(r.Context(), auditHostBlock, id, "")

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
	s.recordAuditAction(r.Context(), auditHostUnblock, id, "")

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

type regenerateEnrollmentTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type rotateCertResponse struct {
	NewKey         bool   `json:"new_key"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	CACertPEM      string `json:"ca_certificate_pem,omitempty"`
}

// handleRotateCert implements POST /api/v1/hosts/{id}/rotate-cert?new_key=...
// (ADR 0004 §7.1 force-rotate).
//
//   - new_key=false (default): the server re-signs the existing public key
//     immediately and returns the new cert. The agent picks it up on the
//     next poll via SaveCertificateAndUpdateHostCert's overlap window.
//   - new_key=true: a pending_rekey flag is set on the host row. The next
//     poll response carries rekey_required + a single-use enrollment token
//     the agent uses to re-enroll its freshly generated keypair.
func (s *Server) handleRotateCert(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	newKey := strings.EqualFold(r.URL.Query().Get("new_key"), "true")

	host, err := s.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host for rotate-cert", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	if newKey {
		if err := s.store.SetPendingRekey(r.Context(), host.ID); err != nil {
			if errors.Is(err, store.ErrRekeyAlreadyPending) {
				writeError(w, http.StatusConflict, "rekey already pending")
				return
			}
			s.logger.Error("set pending rekey", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to schedule rekey")
			return
		}
		s.recordAuditAction(r.Context(), auditHostRotateCertRequested, host.ID, "new_key=true")
		writeJSON(w, http.StatusAccepted, rotateCertResponse{NewKey: true})
		return
	}

	certInfo, err := s.store.GetCertificateInfo(r.Context(), host.ID)
	if err != nil {
		s.logger.Error("get cert info for rotate-cert", "error", err)
		writeError(w, http.StatusInternalServerError, "no current cert to re-sign")
		return
	}
	signed, err := s.signHostCert(r.Context(), host, certInfo)
	if err != nil {
		s.logger.Error("sign cert for rotate-cert", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to sign new cert")
		return
	}
	if err := s.store.SaveCertificateAndUpdateHostCert(r.Context(), host.ID, signed.certPEM, signed.fp, signed.notBefore, signed.notAfter); err != nil {
		s.logger.Error("save rotated cert", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to persist new cert")
		return
	}
	s.metrics.recordSignature(host.CAID)
	s.recordAuditAction(r.Context(), auditHostRotateCertRequested, host.ID, "new_key=false")

	writeJSON(w, http.StatusOK, rotateCertResponse{
		NewKey:         false,
		CertificatePEM: string(signed.certPEM),
		CACertPEM:      string(signed.caCertPEM),
	})
}

// handleReenroll is the explicit re-enrollment endpoint (ADR 0004 §7.1).
// It delegates to mintEnrollmentTokenForHost — identical mechanics to
// handleRegenerateEnrollmentToken — but exists as a separate route so
// operator UIs can present "re-enroll" as a discrete action (e.g. when a
// host has lost its key material), distinct from the "regenerate token"
// fix-up that handleRegenerateEnrollmentToken serves.
func (s *Server) handleReenroll(w http.ResponseWriter, r *http.Request) {
	s.mintEnrollmentTokenForHost(w, r, "reenroll")
}

// handleRegenerateEnrollmentToken mints a fresh single-use enrollment token
// bound to an existing host row (ADR 0004 §7.1 — "regenerates the token
// without churning the row"). Previous active tokens for the same host are
// invalidated atomically. The host row, its IP allocation, group membership,
// and audit history are preserved.
func (s *Server) handleRegenerateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	s.mintEnrollmentTokenForHost(w, r, "regenerate-token")
}

// mintEnrollmentTokenForHost is the shared implementation of the
// regenerate-token and reenroll endpoints. The reason argument flows into
// the audit details column so the timeline distinguishes the two.
func (s *Server) mintEnrollmentTokenForHost(w http.ResponseWriter, r *http.Request, reason string) {
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

	tokenStr := uuid.New().String()
	expiresAt := time.Now().Add(s.tokenTTLFor(r.Context(), host.NetworkID))
	if err := s.store.CreateTokenForHost(r.Context(), host.ID, tokenStr, expiresAt); err != nil {
		s.logger.Error("create enrollment token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to mint token")
		return
	}
	details := host.Name
	if reason != "" {
		details = reason + ": " + host.Name
	}
	s.recordAuditAction(r.Context(), auditHostReenrollRequested, host.ID, details)

	writeJSON(w, http.StatusCreated, regenerateEnrollmentTokenResponse{
		Token:     tokenStr,
		ExpiresAt: expiresAt,
	})
}
