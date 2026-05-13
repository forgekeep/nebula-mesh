package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
	"golang.org/x/crypto/bcrypt"
)

type createOperatorRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	Role        string `json:"role"`
}

func (s *Server) handleCreateOperator(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "operator management requires the admin role")
		return
	}
	var req createOperatorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}
	if err := s.passwordPolicy.Validate(req.Password, strings.ToLower(req.Username)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("hash password", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	op := &models.Operator{
		ID:           uuid.New().String(),
		Username:     req.Username,
		DisplayName:  req.DisplayName,
		PasswordHash: string(hash),
		Role:         req.Role,
	}
	if err := s.store.CreateOperator(r.Context(), op); err != nil {
		s.logger.Error("create operator", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create operator")
		return
	}
	s.recordAuditAction(r.Context(), auditOperatorCreate, op.ID, op.Username)
	writeJSON(w, http.StatusCreated, op)
}

func (s *Server) handleListOperators(w http.ResponseWriter, r *http.Request) {
	ops, err := s.store.ListOperators(r.Context())
	if err != nil {
		s.logger.Error("list operators", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list operators")
		return
	}
	if ops == nil {
		ops = []*models.Operator{}
	}
	writeJSON(w, http.StatusOK, ops)
}

func (s *Server) handleDisableOperator(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.DisableOperator(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "operator not found")
			return
		}
		s.logger.Error("disable operator", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to disable operator")
		return
	}
	s.recordAuditAction(r.Context(), auditOperatorDisable, id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEnableOperator(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.store.EnableOperator(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "operator not found")
			return
		}
		s.logger.Error("enable operator", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to enable operator")
		return
	}
	s.recordAuditAction(r.Context(), auditOperatorEnable, id, "")
	w.WriteHeader(http.StatusNoContent)
}

type createAPIKeyRequest struct {
	Name string `json:"name"`
}

type createAPIKeyResponse struct {
	Key   string                  `json:"key"`   // shown once
	Entry *models.OperatorAPIKey  `json:"entry"`
}

func (s *Server) handleCreateOperatorAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.store.GetOperator(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "operator not found")
			return
		}
		s.logger.Error("get operator", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load operator")
		return
	}
	var req createAPIKeyRequest
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate api key")
		return
	}
	plaintext := hex.EncodeToString(keyBytes)
	sum := sha256.Sum256([]byte(plaintext))

	entry := &models.OperatorAPIKey{
		ID:         uuid.New().String(),
		OperatorID: id,
		Name:       req.Name,
		KeyHash:    hex.EncodeToString(sum[:]),
	}
	if err := s.store.CreateOperatorAPIKey(r.Context(), entry); err != nil {
		s.logger.Error("create api key", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to store api key")
		return
	}
	s.recordAuditAction(r.Context(), auditOperatorAPIKeyCreate, id, entry.ID)
	writeJSON(w, http.StatusCreated, createAPIKeyResponse{Key: plaintext, Entry: entry})
}

func (s *Server) handleRevokeOperatorAPIKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	kid := chi.URLParam(r, "kid")
	if err := s.store.RevokeOperatorAPIKey(r.Context(), kid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "api key not found")
			return
		}
		s.logger.Error("revoke api key", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to revoke api key")
		return
	}
	s.recordAuditAction(r.Context(), auditOperatorAPIKeyRevoke, id, kid)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListOperatorAPIKeys(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	keys, err := s.store.ListOperatorAPIKeys(r.Context(), id)
	if err != nil {
		s.logger.Error("list api keys", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list api keys")
		return
	}
	if keys == nil {
		keys = []*models.OperatorAPIKey{}
	}
	writeJSON(w, http.StatusOK, keys)
}
