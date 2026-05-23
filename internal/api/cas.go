package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
)

type createCARequest struct {
	Name     string `json:"name"`
	Duration string `json:"duration,omitempty"` // e.g. "8760h"
}

type caResponse struct {
	*models.CA
	IsDefault bool `json:"is_default"`
}

func (s *Server) toCAResponse(c *models.CA) caResponse {
	return caResponse{CA: c, IsDefault: c.ID == s.defaultCAID}
}

// handleListCAs returns all CAs visible to the actor. Admin sees all,
// non-admin sees only CAs they own.
func (s *Server) handleListCAs(w http.ResponseWriter, r *http.Request) {
	var (
		cas []*models.CA
		err error
	)
	if s.isActiveAdmin(r.Context()) {
		cas, err = s.store.ListCAs(r.Context())
	} else {
		cas, err = s.store.ListCAsByOwner(r.Context(), ActorOf(r.Context()).ID)
	}
	if err != nil {
		s.logger.Error("list CAs", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list CAs")
		return
	}
	out := make([]caResponse, 0, len(cas))
	for _, c := range cas {
		out = append(out, s.toCAResponse(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetCAByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c, err := s.store.GetCA(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get CA")
		return
	}
	if !s.canAccessCA(r, c) {
		writeError(w, http.StatusForbidden, "you do not own this CA")
		return
	}
	writeJSON(w, http.StatusOK, s.toCAResponse(c))
}

func (s *Server) handleCreateCA(w http.ResponseWriter, r *http.Request) {
	actor := ActorOf(r.Context())
	if s.master == nil {
		writeError(w, http.StatusServiceUnavailable, "CA creation requires NEBULA_MGMT_MASTER_KEY to be configured")
		return
	}

	var req createCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	duration := 365 * 24 * time.Hour
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, "invalid duration")
			return
		}
		duration = d
	}

	mgr, err := pki.NewCA(req.Name, duration)
	if err != nil {
		s.logger.Error("generate CA", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to generate CA")
		return
	}
	rawKey := mgr.RawKey()
	defer keystore.Zeroize(rawKey)

	dek, wrappedDEK, err := s.master.GenerateDEK()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate DEK")
		return
	}
	defer keystore.Zeroize(dek)
	wrappedKey, err := keystore.SealWithDEK(dek, rawKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to encrypt CA key")
		return
	}
	certPEM, err := mgr.CACertPEM()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "marshal CA cert")
		return
	}
	fp, err := mgr.CACertFingerprint()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "fingerprint CA cert")
		return
	}
	now := time.Now()
	c := &models.CA{
		ID:                   uuid.New().String(),
		Name:                 req.Name,
		OwnerOperatorID:      actor.ID,
		CertPEM:              string(certPEM),
		Fingerprint:          fp,
		NotBefore:            mgr.CACert().NotBefore(),
		NotAfter:             mgr.CACert().NotAfter(),
		Status:               models.CAStatusActive,
		EncryptedKeyDEK:      wrappedDEK.Ciphertext,
		NonceDEK:             wrappedDEK.Nonce,
		EncryptedKeyMaterial: wrappedKey.Ciphertext,
		NonceKey:             wrappedKey.Nonce,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := s.store.CreateCA(r.Context(), c); err != nil {
		s.logger.Error("insert CA", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to store CA")
		return
	}
	s.recordAuditAction(r.Context(), auditCACreated, c.ID, c.Name)
	writeJSON(w, http.StatusCreated, s.toCAResponse(c))
}

func (s *Server) handleDeleteCA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	c, err := s.store.GetCA(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load CA")
		return
	}
	if !s.canAccessCA(r, c) {
		writeError(w, http.StatusForbidden, "you do not own this CA")
		return
	}
	if c.ID == s.defaultCAID {
		writeError(w, http.StatusForbidden, "the default CA cannot be deleted")
		return
	}
	if err := s.store.DeleteCA(r.Context(), id); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.recordAuditAction(r.Context(), auditCADeleted, id, "")
	w.WriteHeader(http.StatusNoContent)
}

// canAccessCA checks ownership. Admins bypass.
func (s *Server) canAccessCA(r *http.Request, c *models.CA) bool {
	if s.isActiveAdmin(r.Context()) {
		return true
	}
	return ActorOf(r.Context()).ID == c.OwnerOperatorID
}

func (s *Server) handleRotateCA(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	oldCA, err := s.store.GetCA(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	if err != nil {
		s.logger.Error("get ca", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get CA")
		return
	}
	if !s.canAccessCA(r, oldCA) {
		writeError(w, http.StatusForbidden, "you do not own this CA")
		return
	}

	newCA, err := pki.RotateAndStoreCA(r.Context(), s.store, s.master, s.logger, oldCA)
	if err != nil {
		if errors.Is(err, pki.ErrMasterRequired) {
			writeError(w, http.StatusBadRequest, "master key not configured")
			return
		}
		s.logger.Error("rotate ca", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to rotate CA")
		return
	}

	s.recordAuditAction(r.Context(), auditCARotated, newCA.ID, fmt.Sprintf("predecessor=%s", oldCA.ID))
	writeJSON(w, http.StatusOK, s.toCAResponse(newCA))
}
