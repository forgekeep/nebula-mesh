package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/forgekeep/nebula-mesh/internal/caimport"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type createCARequest struct {
	Name     string `json:"name"`
	Duration string `json:"duration,omitempty"` // e.g. "8760h"
}

type importCARequest struct {
	Name           string
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	Passphrase     []byte
}

func (r *importCARequest) zeroizeSecrets() {
	keystore.Zeroize(r.PrivateKeyPEM)
	keystore.Zeroize(r.Passphrase)
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

	// The CA ID is minted before sealing because both envelope layers bind
	// it as AAD — a (DEK, key-material) pair copied into another CA's row
	// must fail to decrypt rather than sign under the wrong cert.
	caID := uuid.New().String()
	dek, wrappedDEK, err := s.master.GenerateDEK([]byte(caID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate DEK")
		return
	}
	defer keystore.Zeroize(dek)
	wrappedKey, err := keystore.SealWithDEK(dek, rawKey, []byte(caID))
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
		ID:                   caID,
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

func (s *Server) handleImportCA(w http.ResponseWriter, r *http.Request) {
	if !s.secretIngress.Allows(r) {
		writeError(w, http.StatusUpgradeRequired, "CA private key import requires direct TLS, literal-loopback HTTP, or an explicitly trusted local TLS proxy")
		return
	}
	if s.caImporter == nil {
		writeError(w, http.StatusServiceUnavailable, "CA import requires NEBULA_MGMT_MASTER_KEY to be configured")
		return
	}

	request, err := readCAImportMultipart(r)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.Is(err, caimport.ErrInputTooLarge) || errors.As(err, &maxBytesError) {
			writeError(w, http.StatusRequestEntityTooLarge, "CA import input is too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	defer request.zeroizeSecrets()
	actor := ActorOf(r.Context())
	imported, err := s.caImporter.Import(r.Context(), caimport.Request{
		Name:            request.Name,
		OwnerOperatorID: actor.ID,
		CertificatePEM:  request.CertificatePEM,
		PrivateKeyPEM:   request.PrivateKeyPEM,
		Passphrase:      request.Passphrase,
	})
	if err != nil {
		s.writeCAImportError(w, err)
		return
	}
	s.recordAuditAction(r.Context(), auditCAImported, imported.ID, "fingerprint="+imported.Fingerprint)
	writeJSON(w, http.StatusCreated, s.toCAResponse(imported))
}

func readCAImportMultipart(r *http.Request) (importCARequest, error) {
	reader, err := r.MultipartReader()
	if err != nil {
		return importCARequest{}, err
	}

	var request importCARequest
	seen := make(map[string]struct{}, 4)
	fail := func(err error) (importCARequest, error) {
		request.zeroizeSecrets()
		return importCARequest{}, err
	}
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fail(err)
		}

		field := part.FormName()
		if _, duplicate := seen[field]; duplicate {
			_ = part.Close()
			return fail(fmt.Errorf("duplicate multipart field %q", field))
		}
		var maxBytes int64
		switch field {
		case "name":
			maxBytes = 4 << 10
		case "certificate", "private_key":
			maxBytes = 1 << 20
		case "passphrase":
			maxBytes = 64 << 10
		default:
			_ = part.Close()
			return fail(fmt.Errorf("unknown multipart field %q", field))
		}

		value, readErr := io.ReadAll(io.LimitReader(part, maxBytes+1))
		closeErr := part.Close()
		if readErr != nil {
			keystore.Zeroize(value)
			return fail(readErr)
		}
		if closeErr != nil {
			keystore.Zeroize(value)
			return fail(closeErr)
		}
		if int64(len(value)) > maxBytes {
			keystore.Zeroize(value)
			return fail(caimport.ErrInputTooLarge)
		}
		seen[field] = struct{}{}
		switch field {
		case "name":
			request.Name = string(value)
			keystore.Zeroize(value)
		case "certificate":
			request.CertificatePEM = value
		case "private_key":
			request.PrivateKeyPEM = value
		case "passphrase":
			request.Passphrase = value
		}
	}

	for _, required := range []string{"name", "certificate", "private_key"} {
		if _, ok := seen[required]; !ok {
			return fail(fmt.Errorf("missing multipart field %q", required))
		}
	}
	return request, nil
}

func (s *Server) writeCAImportError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, caimport.ErrDuplicateCA):
		writeError(w, http.StatusConflict, "CA already imported")
	case errors.Is(err, caimport.ErrDecryptBusy):
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "another encrypted CA key import is in progress")
	case errors.Is(err, caimport.ErrInputTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "CA import input is too large")
	case errors.Is(err, caimport.ErrKDFLimits):
		writeError(w, http.StatusBadRequest, "encrypted private key exceeds configured KDF limits")
	case errors.Is(err, caimport.ErrInvalidMaterial),
		errors.Is(err, caimport.ErrUnsupportedCurve),
		errors.Is(err, caimport.ErrInvalidValidity),
		errors.Is(err, caimport.ErrKeyMismatch):
		writeError(w, http.StatusBadRequest, "invalid CA certificate or private key")
	case errors.Is(err, caimport.ErrMasterKeyUnavailable):
		writeError(w, http.StatusServiceUnavailable, "CA import requires NEBULA_MGMT_MASTER_KEY to be configured")
	default:
		s.logger.Error("import CA", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to import CA")
	}
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
		if errors.Is(err, store.ErrMeshImportInProgress) {
			writeError(w, http.StatusConflict, "mesh import collection is in progress for this CA")
			return
		}
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
