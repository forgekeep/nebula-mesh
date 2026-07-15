package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/forgekeep/nebula-mesh/internal/bootstraptoken"
	"github.com/forgekeep/nebula-mesh/internal/meshimport"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

const meshImportTokenTTL = 24 * time.Hour

type createMeshImportRequest struct {
	NetworkID     string `json:"network_id"`
	CAID          string `json:"ca_id"`
	ExpectedHosts *int   `json:"expected_hosts,omitempty"`
}

type meshImportTokenResponse struct {
	MeshImport *models.MeshImport `json:"mesh_import"`
	Token      string             `json:"token"`
}

type meshImportWarningAcknowledgement struct {
	Key   string           `json:"key"`
	Issue meshimport.Issue `json:"issue"`
}

type meshImportDetailResponse struct {
	MeshImport              *models.MeshImport                 `json:"mesh_import"`
	HostCount               int                                `json:"host_count"`
	ExpectedCountSatisfied  bool                               `json:"expected_count_satisfied"`
	Report                  meshimport.Report                  `json:"report"`
	WarningAcknowledgements []meshImportWarningAcknowledgement `json:"warning_acknowledgements"`
}

type meshImportFinalizeRequest struct {
	Revision             int64    `json:"revision"`
	InventoryComplete    bool     `json:"inventory_complete"`
	AcknowledgedWarnings []string `json:"acknowledged_warnings"`
}

func (s *Server) handleCreateMeshImport(w http.ResponseWriter, r *http.Request) {
	meshImportNoStore(w)
	var request createMeshImportRequest
	if err := decodeJSONStrict(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.NetworkID == "" || request.CAID == "" {
		writeError(w, http.StatusBadRequest, "network_id and ca_id are required")
		return
	}
	if request.ExpectedHosts != nil && *request.ExpectedHosts <= 0 {
		writeError(w, http.StatusBadRequest, "expected_hosts must be positive")
		return
	}
	network, err := s.store.GetNetwork(r.Context(), request.NetworkID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	if err != nil {
		s.logger.Error("load mesh import network", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load network")
		return
	}
	ca, err := s.store.GetCA(r.Context(), request.CAID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	if err != nil {
		s.logger.Error("load mesh import CA", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load CA")
		return
	}
	networkAllowed, err := s.canAccessNetwork(r.Context(), network)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authorization check failed")
		return
	}
	if !networkAllowed || !s.canAccessCA(r, ca) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	if network.CAID != ca.ID {
		writeError(w, http.StatusConflict, "Network is not bound to the selected CA")
		return
	}
	if ca.Status != models.CAStatusActive {
		writeError(w, http.StatusConflict, "CA must be active")
		return
	}
	rawToken, err := bootstraptoken.Generate(bootstraptoken.PurposeMeshImport)
	if err != nil {
		s.logger.Error("generate mesh import token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate import token")
		return
	}
	now := s.now()
	item := &models.MeshImport{
		ID: uuid.NewString(), NetworkID: network.ID, CAID: ca.ID,
		OwnerOperatorID: ActorOf(r.Context()).ID, Status: models.MeshImportStatusCollecting,
		ExpectedHosts: request.ExpectedHosts, TokenHash: bootstraptoken.Hash(rawToken),
		TokenExpiresAt: now.Add(meshImportTokenTTL), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateMeshImport(r.Context(), item); err != nil {
		s.writeMeshImportCreateError(w, err)
		return
	}
	s.recordAuditAction(r.Context(), auditMeshImportCreated, item.ID, fmt.Sprintf("network=%s ca=%s", item.NetworkID, item.CAID))
	writeJSON(w, http.StatusCreated, meshImportTokenResponse{MeshImport: item, Token: rawToken})
}

func (s *Server) handleListMeshImports(w http.ResponseWriter, r *http.Request) {
	meshImportNoStore(w)
	var (
		items []*models.MeshImport
		err   error
	)
	if s.isActiveAdmin(r.Context()) {
		items, err = s.store.ListMeshImports(r.Context())
	} else {
		items, err = s.store.ListMeshImportsByOwner(r.Context(), ActorOf(r.Context()).ID)
	}
	if err != nil {
		s.logger.Error("list mesh imports", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list mesh imports")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleGetMeshImport(w http.ResponseWriter, r *http.Request) {
	meshImportNoStore(w)
	item, ok := s.loadAccessibleMeshImport(w, r)
	if !ok {
		return
	}
	detail, err := s.buildMeshImportDetail(r, item)
	if err != nil {
		s.logger.Error("build mesh import preview", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build mesh import preview")
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleFinalizeMeshImport(w http.ResponseWriter, r *http.Request) {
	meshImportNoStore(w)
	item, ok := s.loadAccessibleMeshImport(w, r)
	if !ok {
		return
	}
	var request meshImportFinalizeRequest
	if err := decodeJSONStrict(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !request.InventoryComplete {
		writeError(w, http.StatusBadRequest, "inventory_complete must be true")
		return
	}
	if item.Status != models.MeshImportStatusCollecting || request.Revision != item.Revision {
		writeError(w, http.StatusConflict, "mesh import changed since preview")
		return
	}
	detail, err := s.buildMeshImportDetail(r, item)
	if err != nil {
		s.logger.Error("build mesh import finalize preview", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to build mesh import preview")
		return
	}
	if !detail.ExpectedCountSatisfied {
		writeError(w, http.StatusConflict, "expected host count is not satisfied")
		return
	}
	if len(detail.Report.Blockers) != 0 {
		writeError(w, http.StatusConflict, "mesh import preview has blockers")
		return
	}
	expectedWarnings := make(map[string]struct{}, len(detail.WarningAcknowledgements))
	for _, warning := range detail.WarningAcknowledgements {
		expectedWarnings[warning.Key] = struct{}{}
	}
	acknowledged := make(map[string]struct{}, len(request.AcknowledgedWarnings))
	for _, key := range request.AcknowledgedWarnings {
		if _, exists := expectedWarnings[key]; !exists {
			writeError(w, http.StatusConflict, "warning acknowledgements do not match the current preview")
			return
		}
		acknowledged[key] = struct{}{}
	}
	if len(acknowledged) != len(expectedWarnings) {
		writeError(w, http.StatusConflict, "all warnings must be acknowledged")
		return
	}
	firewallJSON, err := json.Marshal(detail.Report.Proposal.Firewall)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encode mesh import proposal")
		return
	}
	hosts := make([]store.MeshImportFinalizeHost, 0, len(detail.Report.Proposal.Hosts))
	for _, proposal := range detail.Report.Proposal.Hosts {
		hosts = append(hosts, store.MeshImportFinalizeHost{SnapshotID: proposal.SnapshotID, Host: proposal.Host})
	}
	if err := s.store.FinalizeMeshImport(r.Context(), store.MeshImportFinalizeInput{
		ID: item.ID, Revision: item.Revision, Hosts: hosts, FirewallJSON: string(firewallJSON),
		Blocklist: detail.Report.Proposal.Blocklist, Now: s.now(),
	}); err != nil {
		if errors.Is(err, store.ErrMeshImportConflict) || errors.Is(err, store.ErrMeshImportNotCollecting) {
			writeError(w, http.StatusConflict, "mesh import changed since preview")
			return
		}
		s.logger.Error("finalize mesh import", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to finalize mesh import")
		return
	}
	finalized, err := s.store.GetMeshImport(r.Context(), item.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload finalized mesh import")
		return
	}
	s.recordAuditAction(r.Context(), auditMeshImportFinalized, item.ID, fmt.Sprintf("hosts=%d revision=%d", len(hosts), item.Revision))
	s.emit("mesh_import.finalized", map[string]any{
		"mesh_import_id": item.ID, "network_id": item.NetworkID, "ca_id": item.CAID, "host_count": len(hosts),
	})
	for _, proposal := range hosts {
		host := proposal.Host
		host.Status = models.HostStatusEnrolled
		data := hostEventData(&host)
		data["fingerprint"] = host.CertFingerprint
		s.emit("host.enrolled", data)
	}
	writeJSON(w, http.StatusOK, finalized)
}

func (s *Server) buildMeshImportDetail(r *http.Request, item *models.MeshImport) (*meshImportDetailResponse, error) {
	network, err := s.store.GetNetwork(r.Context(), item.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("load import network: %w", err)
	}
	ca, err := s.store.GetCA(r.Context(), item.CAID)
	if err != nil {
		return nil, fmt.Errorf("load import CA: %w", err)
	}
	snapshots, err := s.store.ListMeshImportSnapshots(r.Context(), item.ID)
	if err != nil {
		return nil, fmt.Errorf("load import snapshots: %w", err)
	}
	report := meshimport.BuildPreview(meshimport.PreviewInput{
		Session: item, Network: network, CA: ca, Snapshots: snapshots, Now: s.now(),
	})
	warnings := make([]meshImportWarningAcknowledgement, 0, len(report.Warnings))
	for _, issue := range report.Warnings {
		warnings = append(warnings, meshImportWarningAcknowledgement{Key: meshimport.WarningAcknowledgementKey(issue), Issue: issue})
	}
	expectedSatisfied := true
	if item.ExpectedHosts != nil {
		expectedSatisfied = *item.ExpectedHosts == len(snapshots)
	}
	return &meshImportDetailResponse{
		MeshImport: item, HostCount: len(snapshots), ExpectedCountSatisfied: expectedSatisfied,
		Report: report, WarningAcknowledgements: warnings,
	}, nil
}

func (s *Server) handleRotateMeshImportToken(w http.ResponseWriter, r *http.Request) {
	meshImportNoStore(w)
	item, ok := s.loadAccessibleMeshImport(w, r)
	if !ok {
		return
	}
	rawToken, err := bootstraptoken.Generate(bootstraptoken.PurposeMeshImport)
	if err != nil {
		s.logger.Error("generate rotated mesh import token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate import token")
		return
	}
	now := s.now()
	expiresAt := now.Add(meshImportTokenTTL)
	if err := s.store.RotateMeshImportToken(r.Context(), item.ID, bootstraptoken.Hash(rawToken), expiresAt, now); err != nil {
		if errors.Is(err, store.ErrMeshImportNotCollecting) {
			writeError(w, http.StatusConflict, "mesh import is not collecting")
			return
		}
		s.logger.Error("rotate mesh import token", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to rotate import token")
		return
	}
	item.TokenExpiresAt = expiresAt
	item.UpdatedAt = now
	s.recordAuditAction(r.Context(), auditMeshImportTokenRotated, item.ID, "")
	writeJSON(w, http.StatusCreated, meshImportTokenResponse{MeshImport: item, Token: rawToken})
}

func (s *Server) handleCancelMeshImport(w http.ResponseWriter, r *http.Request) {
	meshImportNoStore(w)
	item, ok := s.loadAccessibleMeshImport(w, r)
	if !ok {
		return
	}
	if err := s.store.CancelMeshImport(r.Context(), item.ID, "operator canceled", s.now()); err != nil {
		if errors.Is(err, store.ErrMeshImportNotCollecting) {
			writeError(w, http.StatusConflict, "mesh import is not collecting")
			return
		}
		s.logger.Error("cancel mesh import", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to cancel mesh import")
		return
	}
	canceled, err := s.store.GetMeshImport(r.Context(), item.ID)
	if err != nil {
		s.logger.Error("reload canceled mesh import", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load canceled mesh import")
		return
	}
	s.recordAuditAction(r.Context(), auditMeshImportCanceled, item.ID, "")
	writeJSON(w, http.StatusOK, canceled)
}

func (s *Server) loadAccessibleMeshImport(w http.ResponseWriter, r *http.Request) (*models.MeshImport, bool) {
	item, err := s.store.GetMeshImport(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "mesh import not found")
		return nil, false
	}
	if err != nil {
		s.logger.Error("load mesh import", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load mesh import")
		return nil, false
	}
	actor := ActorOf(r.Context())
	if actor == nil || (item.OwnerOperatorID != actor.ID && !s.isActiveAdmin(r.Context())) {
		writeError(w, http.StatusForbidden, "forbidden")
		return nil, false
	}
	return item, true
}

func (s *Server) writeMeshImportCreateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrMeshImportInProgress),
		errors.Is(err, store.ErrMeshImportScopeInvalid),
		errors.Is(err, store.ErrDuplicateEntry):
		writeError(w, http.StatusConflict, "Network or CA is not eligible for mesh import")
	default:
		s.logger.Error("create mesh import", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create mesh import")
	}
}

func meshImportNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
