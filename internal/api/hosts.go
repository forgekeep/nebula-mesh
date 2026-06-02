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

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type createHostRequest struct {
	NetworkID  string               `json:"network_id"`
	Name       string               `json:"name"`
	NebulaIPs  []string             `json:"nebula_ips"`
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

type updateHostRequest struct {
	Name       *string              `json:"name,omitempty"`
	NebulaIPs  *[]string            `json:"nebula_ips,omitempty"`
	Groups     *[]string            `json:"groups,omitempty"`
	Role       *string              `json:"role,omitempty"`
	PublicIP   *string              `json:"public_ip,omitempty"`
	ListenPort *int                 `json:"listen_port,omitempty"`
	Advanced   *models.HostAdvanced `json:"advanced,omitempty"`
}

// Bounds on host fields that are embedded in the signed Nebula certificate and
// then distributed to every peer; without caps an operator could bloat certs
// mesh-wide (#186). Generous relative to real use, but bounded.
const (
	maxHostNameLen  = 255
	maxGroupNameLen = 64
	maxHostGroups   = 64
)

// validateHostName bounds the host name length.
func validateHostName(name string) error {
	if len(name) > maxHostNameLen {
		return fmt.Errorf("name must be at most %d characters", maxHostNameLen)
	}
	return nil
}

// validateHostGroups bounds the group count and each group's length, and keeps
// the existing non-empty rule.
func validateHostGroups(groups []string) error {
	if len(groups) > maxHostGroups {
		return fmt.Errorf("at most %d groups allowed, got %d", maxHostGroups, len(groups))
	}
	for _, g := range groups {
		if strings.TrimSpace(g) == "" {
			return fmt.Errorf("group names must not be empty")
		}
		if len(g) > maxGroupNameLen {
			return fmt.Errorf("group name must be at most %d characters", maxGroupNameLen)
		}
	}
	return nil
}

func (s *Server) handleCreateHost(w http.ResponseWriter, r *http.Request) {
	var req createHostRequest
	if err := decodeJSONStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Name == "" || len(req.NebulaIPs) == 0 || req.NetworkID == "" {
		writeError(w, http.StatusBadRequest, "name, nebula_ips, and network_id are required")
		return
	}

	network, err := s.store.GetNetwork(r.Context(), req.NetworkID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusBadRequest, "network not found")
		return
	}
	if err != nil {
		s.logger.Error("get network for host create", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load network")
		return
	}
	netOK, err := s.canAccessNetwork(r.Context(), network)
	if err != nil {
		s.logger.Error("authz check for host create", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !netOK {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	if err := validateHostIPs(r.Context(), s.store, req.NetworkID, req.NebulaIPs, ""); err != nil {
		if IsHostIPValidationError(err) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.logger.Error("validate host ips", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to validate nebula_ips")
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

	// Host inherits the network's CA. Combined with the canAccessNetwork
	// gate above, this binds new hosts to the same trust domain as the
	// network's operator (closes the GHSA-598g class of cross-tenant cert
	// issuance via host create + rotate-cert). The defaultCAID fallback
	// preserves backward compatibility for admin-created networks via the
	// CAID-less /api/v1/networks endpoint (out-of-scope follow-up).
	caID := network.CAID
	if caID == "" {
		caID = s.defaultCAID
	}
	now := time.Now()
	host := &models.Host{
		ID:           uuid.New().String(),
		NetworkID:    req.NetworkID,
		Name:         req.Name,
		NebulaIPs:    req.NebulaIPs,
		Groups:       req.Groups,
		Role:         role,
		IsLighthouse: role == models.HostRoleLighthouse,
		IsRelay:      role == models.HostRoleRelay,
		PublicIP:     req.PublicIP,
		ListenPort:   req.ListenPort,
		Status:       models.HostStatusPending,
		Advanced:     req.Advanced,
		CAID:         caID,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if host.Groups == nil {
		host.Groups = []string{}
	}
	if err := validateHostName(host.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateHostGroups(host.Groups); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rawToken := uuid.New().String()
	token := &models.EnrollmentToken{
		ID:        uuid.New().String(),
		HostID:    host.ID,
		TokenHash: models.HashEnrollmentToken(rawToken),
		ExpiresAt: now.Add(s.tokenTTLFor(r.Context(), host.NetworkID)),
		CreatedAt: now,
	}
	if err := s.store.CreateHostAndToken(r.Context(), host, token); err != nil {
		// Reachable only via a TOCTOU race between concurrent host writes: the
		// validateHostIPs fast-path above returns 400 for any collision visible
		// at request time, so reaching the store's UNIQUE(network_id, address)
		// guard means another writer claimed the IP in between.
		if errors.Is(err, store.ErrIPTaken) {
			writeError(w, http.StatusConflict, "one or more nebula_ips are already assigned to another host in this network")
			return
		}
		s.logger.Error("create host and token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create host")
		return
	}
	s.recordAuditAction(r.Context(), auditHostCreate, host.ID, host.Name)

	writeJSON(w, http.StatusCreated, createHostResponse{
		Host:            host,
		EnrollmentToken: rawToken,
	})
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	filter := store.HostFilter{
		NetworkID: r.URL.Query().Get("network_id"),
		Group:     r.URL.Query().Get("group"),
		Status:    models.HostStatus(r.URL.Query().Get("status")),
		Limit:     1000,
	}

	// Non-admins are scoped to hosts under CAs they own. Push that scope into
	// the query rather than filtering the result in Go: a global LIMIT applied
	// before the ownership filter could drop an operator's own hosts out of the
	// window, silently undercounting once the deployment exceeds the limit.
	if !s.isActiveAdmin(r.Context()) {
		actor := ActorOf(r.Context())
		if actor == nil {
			writeJSON(w, http.StatusOK, []*models.Host{})
			return
		}
		cas, err := s.store.ListCAsByOwner(r.Context(), actor.ID)
		if err != nil {
			s.logger.Error("list cas by owner", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to check permissions")
			return
		}
		if len(cas) == 0 {
			writeJSON(w, http.StatusOK, []*models.Host{})
			return
		}
		caIDs := make([]string, len(cas))
		for i, ca := range cas {
			caIDs[i] = ca.ID
		}
		filter.CAIDs = caIDs
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
	ok, err := s.canAccessHost(r.Context(), host)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	writeJSON(w, http.StatusOK, host)
}

func (s *Server) handleDeleteHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := s.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host for delete", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}
	ok, err := s.canAccessHost(r.Context(), host)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
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
	existing, err := s.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host for block", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}
	ok, err := s.canAccessHost(r.Context(), existing)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
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
	existing, err := s.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host for unblock", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}
	ok, err := s.canAccessHost(r.Context(), existing)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
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
	if !s.isActiveAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "blocklist access requires the admin role")
		return
	}
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
	ok, err := s.canAccessHost(r.Context(), host)
	if err != nil {
		s.logger.Error("authz check for rotate-cert", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	// Durable revocation (GHSA-339v-266x-79xr): a blocked host must be explicitly
	// unblocked before any cert rotation/re-issuance.
	if host.Status == models.HostStatusBlocked {
		writeError(w, http.StatusConflict, "host is blocked; unblock before rotating its certificate")
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
	signed, err := s.signHostCert(r.Context(), host, certInfo, s.now())
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
	ok, err := s.canAccessHost(r.Context(), host)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	// Durable revocation (GHSA-339v-266x-79xr): never mint a re-enroll token for
	// a blocked host. The enroll handler enforces the same guard, but failing
	// fast here gives the operator a clear signal to unblock first.
	if host.Status == models.HostStatusBlocked {
		writeError(w, http.StatusConflict, "host is blocked; unblock before re-enrolling")
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

func (s *Server) handleUpdateHost(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Load host by ID
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
	ok, err := s.canAccessHost(r.Context(), host)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	// Decode request body (lenient for PATCH, forward-compatible)
	var req updateHostRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Snapshot before state for diff and triggers
	before := *host
	if before.Advanced != nil {
		beforeAdv := *before.Advanced
		before.Advanced = &beforeAdv
	}

	// Validate and merge fields
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "name must not be empty")
			return
		}
		if err := validateHostName(name); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		host.Name = name
	}

	if req.NebulaIPs != nil {
		if err := validateHostIPs(r.Context(), s.store, host.NetworkID, *req.NebulaIPs, host.ID); err != nil {
			if IsHostIPValidationError(err) {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.logger.Error("validate host ips", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to validate nebula_ips")
			return
		}
		host.NebulaIPs = *req.NebulaIPs
	}

	if req.Groups != nil {
		if err := validateHostGroups(*req.Groups); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		host.Groups = *req.Groups
	}

	if req.Role != nil {
		role := models.HostRole(*req.Role)
		if !models.ValidRole(role) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid role: %q", *req.Role))
			return
		}
		host.Role = role
		host.IsLighthouse = role == models.HostRoleLighthouse
		host.IsRelay = role == models.HostRoleRelay
	}

	if req.PublicIP != nil {
		publicIP := strings.TrimSpace(*req.PublicIP)
		if publicIP != "" {
			if _, err := models.ValidateIPAddr("public_ip", publicIP); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		host.PublicIP = publicIP
	}

	if req.ListenPort != nil {
		if *req.ListenPort < 0 || *req.ListenPort > 65535 {
			writeError(w, http.StatusBadRequest, "listen_port must be between 0 and 65535")
			return
		}
		host.ListenPort = *req.ListenPort
	}

	if req.Advanced != nil {
		if err := validateHostAdvanced(req.Advanced); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		host.Advanced = req.Advanced
	}

	// Validate role reachability
	if err := models.ValidateRoleReachability(host.Role, host.PublicIP, host.ListenPort); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Compute diff
	diffJSON, hasChanges, err := models.HostDiff(&before, host)
	if err != nil {
		s.logger.Error("compute diff", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to compute diff")
		return
	}

	// If no changes, return 200 without updating
	if !hasChanges {
		writeJSON(w, http.StatusOK, host)
		return
	}

	// Update timestamp and persist
	host.UpdatedAt = time.Now()
	if err := s.store.UpdateHost(r.Context(), host); err != nil {
		// Reachable only via a TOCTOU race between concurrent host writes: the
		// validateHostIPs fast-path above returns 400 for any collision visible
		// at request time, so reaching the store's UNIQUE(network_id, address)
		// guard means another writer claimed the IP in between.
		if errors.Is(err, store.ErrIPTaken) {
			writeError(w, http.StatusConflict, "one or more nebula_ips are already assigned to another host in this network")
			return
		}
		s.logger.Error("update host", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update host")
		return
	}

	// Task 1.4: Re-publish triggers
	// Force re-publish config for this host
	if err := s.store.UpdateHostConfigVersion(r.Context(), host.ID, 0); err != nil {
		s.logger.Error("reset host config version", "host", host.ID, "error", err)
	}

	// If role changed, bump network config version for peer updates
	if before.Role != host.Role {
		if err := s.store.BumpNetworkConfigVersion(r.Context(), host.NetworkID); err != nil {
			s.logger.Error("bump network config version", "network", host.NetworkID, "error", err)
		}
	}

	// If name or any IP changed, set pending rekey for cert re-enrollment
	ipsEqual := len(before.NebulaIPs) == len(host.NebulaIPs)
	if ipsEqual {
		for i := range before.NebulaIPs {
			if before.NebulaIPs[i] != host.NebulaIPs[i] {
				ipsEqual = false
				break
			}
		}
	}
	if before.Name != host.Name || !ipsEqual {
		if err := s.store.SetPendingRekey(r.Context(), host.ID); err != nil {
			if !errors.Is(err, store.ErrRekeyAlreadyPending) {
				s.logger.Error("set pending rekey", "host", host.ID, "error", err)
			}
			// Idempotent: ErrRekeyAlreadyPending is success (rekey already scheduled)
		}
		// Reload host to get PendingRekey flag in response
		freshHost, err := s.store.GetHost(r.Context(), host.ID)
		if err == nil {
			host = freshHost
		}
	}

	// Record audit entry with diff
	s.recordAuditAction(r.Context(), auditHostUpdate, host.ID, string(diffJSON))

	writeJSON(w, http.StatusOK, host)
}
