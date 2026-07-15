package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/forgekeep/nebula-mesh/internal/bootstraptoken"
	"github.com/forgekeep/nebula-mesh/internal/meshimport"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

const webMeshImportTokenTTL = 24 * time.Hour

func (w *Web) handleMeshImportsList(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	var (
		items []*models.MeshImport
		err   error
	)
	if op.Role == models.OperatorRoleAdmin {
		items, err = w.store.ListMeshImports(r.Context())
	} else {
		items, err = w.store.ListMeshImportsByOwner(r.Context(), op.ID)
	}
	if err != nil {
		w.logger.Error("list mesh imports", "error", err)
		http.Error(rw, "Failed to load mesh imports", http.StatusInternalServerError)
		return
	}
	w.renderForRequest(rw, r, "mesh_imports.html", map[string]any{
		"Active": "mesh-imports", "MeshImports": items,
	})
}

func (w *Web) handleMeshImportNew(rw http.ResponseWriter, r *http.Request) {
	w.renderMeshImportNew(rw, r, http.StatusOK, "")
}

func (w *Web) handleMeshImportCreate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "Bad request", http.StatusBadRequest)
		return
	}
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	networkID := strings.TrimSpace(r.FormValue("network_id"))
	caID := strings.TrimSpace(r.FormValue("ca_id"))
	if networkID == "" || caID == "" {
		w.renderMeshImportNew(rw, r, http.StatusBadRequest, "Network and CA are required")
		return
	}
	var expectedHosts *int
	if raw := strings.TrimSpace(r.FormValue("expected_hosts")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			w.renderMeshImportNew(rw, r, http.StatusBadRequest, "Expected hosts must be a positive number")
			return
		}
		expectedHosts = &value
	}
	network, err := w.store.GetNetwork(r.Context(), networkID)
	if errors.Is(err, store.ErrNotFound) {
		w.renderMeshImportNew(rw, r, http.StatusBadRequest, "Network not found")
		return
	}
	if err != nil {
		http.Error(rw, "Failed to load Network", http.StatusInternalServerError)
		return
	}
	cas, err := w.accessibleActiveCAs(r.Context(), op)
	if err != nil {
		http.Error(rw, "Failed to load CAs", http.StatusInternalServerError)
		return
	}
	networks, err := w.accessibleNetworks(r.Context(), op)
	if err != nil {
		http.Error(rw, "Failed to load Networks", http.StatusInternalServerError)
		return
	}
	if !containsCAID(cas, caID) || !containsNetworkID(networks, networkID) {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}
	if network.CAID != caID {
		w.renderMeshImportNew(rw, r, http.StatusConflict, "Network is not bound to the selected CA")
		return
	}
	rawToken, err := bootstraptoken.Generate(bootstraptoken.PurposeMeshImport)
	if err != nil {
		w.logger.Error("generate mesh import token", "error", err)
		http.Error(rw, "Failed to generate import token", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	item := &models.MeshImport{
		ID: uuid.NewString(), NetworkID: networkID, CAID: caID, OwnerOperatorID: op.ID,
		Status: models.MeshImportStatusCollecting, ExpectedHosts: expectedHosts,
		TokenHash: bootstraptoken.Hash(rawToken), TokenExpiresAt: now.Add(webMeshImportTokenTTL),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := w.store.CreateMeshImport(r.Context(), item); err != nil {
		if errors.Is(err, store.ErrMeshImportInProgress) || errors.Is(err, store.ErrMeshImportScopeInvalid) || errors.Is(err, store.ErrDuplicateEntry) {
			w.renderMeshImportNew(rw, r, http.StatusConflict, "Network or CA is not eligible for mesh import")
			return
		}
		w.logger.Error("create mesh import", "error", err)
		http.Error(rw, "Failed to create mesh import", http.StatusInternalServerError)
		return
	}
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "mesh_import.created", item.ID, fmt.Sprintf("network=%s ca=%s", networkID, caID))
	w.renderMeshImportDetail(rw, r, http.StatusCreated, item, rawToken, "")
}

func (w *Web) handleMeshImportDetail(rw http.ResponseWriter, r *http.Request) {
	item, ok := w.loadAccessibleMeshImport(rw, r)
	if !ok {
		return
	}
	w.renderMeshImportDetail(rw, r, http.StatusOK, item, "", r.URL.Query().Get("error"))
}

func (w *Web) handleMeshImportRotateToken(rw http.ResponseWriter, r *http.Request) {
	item, ok := w.loadAccessibleMeshImport(rw, r)
	if !ok {
		return
	}
	rawToken, err := bootstraptoken.Generate(bootstraptoken.PurposeMeshImport)
	if err != nil {
		http.Error(rw, "Failed to generate import token", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	expiresAt := now.Add(webMeshImportTokenTTL)
	if err := w.store.RotateMeshImportToken(r.Context(), item.ID, bootstraptoken.Hash(rawToken), expiresAt, now); err != nil {
		if errors.Is(err, store.ErrMeshImportNotCollecting) {
			w.renderMeshImportDetail(rw, r, http.StatusConflict, item, "", "Mesh import is not collecting")
			return
		}
		http.Error(rw, "Failed to rotate import token", http.StatusInternalServerError)
		return
	}
	item.TokenExpiresAt = expiresAt
	item.UpdatedAt = now
	op := w.session.CurrentOperator(r)
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "mesh_import.token_rotated", item.ID, "")
	w.renderMeshImportDetail(rw, r, http.StatusCreated, item, rawToken, "")
}

func (w *Web) handleMeshImportCancel(rw http.ResponseWriter, r *http.Request) {
	item, ok := w.loadAccessibleMeshImport(rw, r)
	if !ok {
		return
	}
	if err := w.store.CancelMeshImport(r.Context(), item.ID, "operator canceled", time.Now()); err != nil {
		if errors.Is(err, store.ErrMeshImportNotCollecting) {
			w.renderMeshImportDetail(rw, r, http.StatusConflict, item, "", "Mesh import is not collecting")
			return
		}
		http.Error(rw, "Failed to cancel mesh import", http.StatusInternalServerError)
		return
	}
	op := w.session.CurrentOperator(r)
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "mesh_import.canceled", item.ID, "")
	http.Redirect(rw, r, "/ui/mesh-imports/"+item.ID, http.StatusSeeOther)
}

func (w *Web) handleMeshImportFinalize(rw http.ResponseWriter, r *http.Request) {
	item, ok := w.loadAccessibleMeshImport(rw, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "Bad request", http.StatusBadRequest)
		return
	}
	revision, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("revision")), 10, 64)
	if err != nil || revision != item.Revision {
		w.renderMeshImportDetail(rw, r, http.StatusConflict, item, "", "Mesh import changed since preview")
		return
	}
	if r.FormValue("inventory_complete") != "true" {
		w.renderMeshImportDetail(rw, r, http.StatusBadRequest, item, "", "Confirm that the inventory is complete")
		return
	}
	report, snapshots, warningKeys, err := w.buildMeshImportPreview(r, item)
	if err != nil {
		http.Error(rw, "Failed to build mesh import preview", http.StatusInternalServerError)
		return
	}
	if item.Status != models.MeshImportStatusCollecting || (item.ExpectedHosts != nil && *item.ExpectedHosts != len(snapshots)) || len(report.Blockers) != 0 {
		w.renderMeshImportDetail(rw, r, http.StatusConflict, item, "", "Resolve all blockers and satisfy the expected host count before finalize")
		return
	}
	expected := make(map[string]struct{}, len(warningKeys))
	for _, key := range warningKeys {
		expected[key] = struct{}{}
	}
	acknowledged := make(map[string]struct{}, len(r.Form["acknowledged_warnings"]))
	for _, key := range r.Form["acknowledged_warnings"] {
		if _, exists := expected[key]; !exists {
			w.renderMeshImportDetail(rw, r, http.StatusConflict, item, "", "Warning acknowledgements no longer match the preview")
			return
		}
		acknowledged[key] = struct{}{}
	}
	if len(acknowledged) != len(expected) {
		w.renderMeshImportDetail(rw, r, http.StatusConflict, item, "", "Acknowledge every warning before finalize")
		return
	}
	firewallJSON, err := json.Marshal(report.Proposal.Firewall)
	if err != nil {
		http.Error(rw, "Failed to encode mesh import proposal", http.StatusInternalServerError)
		return
	}
	hosts := make([]store.MeshImportFinalizeHost, 0, len(report.Proposal.Hosts))
	for _, proposal := range report.Proposal.Hosts {
		hosts = append(hosts, store.MeshImportFinalizeHost{SnapshotID: proposal.SnapshotID, Host: proposal.Host})
	}
	if err := w.store.FinalizeMeshImport(r.Context(), store.MeshImportFinalizeInput{
		ID: item.ID, Revision: item.Revision, Hosts: hosts, FirewallJSON: string(firewallJSON),
		Blocklist: report.Proposal.Blocklist, Now: time.Now(),
	}); err != nil {
		if errors.Is(err, store.ErrMeshImportConflict) || errors.Is(err, store.ErrMeshImportNotCollecting) {
			w.renderMeshImportDetail(rw, r, http.StatusConflict, item, "", "Mesh import changed since preview")
			return
		}
		w.logger.Error("finalize mesh import", "error", err)
		http.Error(rw, "Failed to finalize mesh import", http.StatusInternalServerError)
		return
	}
	op := w.session.CurrentOperator(r)
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "mesh_import.finalized", item.ID, fmt.Sprintf("hosts=%d revision=%d", len(hosts), item.Revision))
	w.emitLifecycle("mesh_import.finalized", map[string]any{
		"mesh_import_id": item.ID, "network_id": item.NetworkID, "ca_id": item.CAID, "host_count": len(hosts),
	})
	for _, proposal := range hosts {
		host := proposal.Host
		w.emitLifecycle("host.enrolled", map[string]any{
			"host_id": host.ID, "host_name": host.Name, "network_id": host.NetworkID,
			"ca_id": host.CAID, "fingerprint": host.CertFingerprint,
		})
	}
	http.Redirect(rw, r, "/ui/mesh-imports/"+item.ID, http.StatusSeeOther)
}

func (w *Web) loadAccessibleMeshImport(rw http.ResponseWriter, r *http.Request) (*models.MeshImport, bool) {
	item, err := w.store.GetMeshImport(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return nil, false
	}
	if err != nil {
		http.Error(rw, "Failed to load mesh import", http.StatusInternalServerError)
		return nil, false
	}
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return nil, false
	}
	if op.Role != models.OperatorRoleAdmin && item.OwnerOperatorID != op.ID {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return nil, false
	}
	return item, true
}

func (w *Web) renderMeshImportNew(rw http.ResponseWriter, r *http.Request, status int, message string) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	networks, err := w.accessibleNetworks(r.Context(), op)
	if err != nil {
		http.Error(rw, "Failed to load Networks", http.StatusInternalServerError)
		return
	}
	cas, err := w.accessibleActiveCAs(r.Context(), op)
	if err != nil {
		http.Error(rw, "Failed to load CAs", http.StatusInternalServerError)
		return
	}
	w.renderForRequestWithStatus(rw, r, status, "mesh_import_new.html", map[string]any{
		"Active": "mesh-imports", "Networks": networks, "CAs": cas, "Error": message,
	})
}

func (w *Web) renderMeshImportDetail(rw http.ResponseWriter, r *http.Request, status int, item *models.MeshImport, rawToken, message string) {
	report, snapshots, warningKeys, err := w.buildMeshImportPreview(r, item)
	if err != nil {
		http.Error(rw, "Failed to build mesh import preview", http.StatusInternalServerError)
		return
	}
	warnings := make([]map[string]any, 0, len(report.Warnings))
	for index, issue := range report.Warnings {
		warnings = append(warnings, map[string]any{"Key": warningKeys[index], "Issue": issue})
	}
	expectedSatisfied := item.ExpectedHosts == nil || *item.ExpectedHosts == len(snapshots)
	w.renderForRequestWithStatus(rw, r, status, "mesh_import_detail.html", map[string]any{
		"Active": "mesh-imports", "MeshImport": item, "Snapshots": snapshots,
		"HostCount": len(snapshots), "Token": rawToken, "Error": message,
		"Report": report, "Warnings": warnings, "ExpectedSatisfied": expectedSatisfied,
	})
}

func (w *Web) buildMeshImportPreview(r *http.Request, item *models.MeshImport) (meshimport.Report, []*models.MeshImportSnapshot, []string, error) {
	network, err := w.store.GetNetwork(r.Context(), item.NetworkID)
	if err != nil {
		return meshimport.Report{}, nil, nil, err
	}
	ca, err := w.store.GetCA(r.Context(), item.CAID)
	if err != nil {
		return meshimport.Report{}, nil, nil, err
	}
	snapshots, err := w.store.ListMeshImportSnapshots(r.Context(), item.ID)
	if err != nil {
		return meshimport.Report{}, nil, nil, err
	}
	report := meshimport.BuildPreview(meshimport.PreviewInput{
		Session: item, Network: network, CA: ca, Snapshots: snapshots, Now: time.Now(),
	})
	warningKeys := make([]string, 0, len(report.Warnings))
	for _, issue := range report.Warnings {
		warningKeys = append(warningKeys, meshimport.WarningAcknowledgementKey(issue))
	}
	return report, snapshots, warningKeys, nil
}

func containsNetworkID(networks []*models.Network, id string) bool {
	for _, network := range networks {
		if network.ID == id {
			return true
		}
	}
	return false
}
