package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/forgekeep/nebula-mesh/internal/config"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// webhookSubRequest is the create/update body. Secret is write-only: on create
// a non-empty value enables signing; on update nil keeps the existing secret,
// "" clears it, and a value replaces it. Active is a pointer so update can omit
// it to keep the current state (create defaults to true).
type webhookSubRequest struct {
	URL          string   `json:"url"`
	Events       []string `json:"events,omitempty"`
	Active       *bool    `json:"active,omitempty"`
	AllowPrivate bool     `json:"allow_private,omitempty"`
	Secret       *string  `json:"secret,omitempty"`
}

func (s *Server) canAccessWebhookSub(r *http.Request, sub *models.WebhookSubscription) bool {
	if s.isActiveAdmin(r.Context()) {
		return true
	}
	return ActorOf(r.Context()).ID == sub.OwnerOperatorID
}

// handleListWebhookSubscriptions lists subscriptions visible to the actor.
func (s *Server) handleListWebhookSubscriptions(w http.ResponseWriter, r *http.Request) {
	var (
		subs []*models.WebhookSubscription
		err  error
	)
	if s.isActiveAdmin(r.Context()) {
		subs, err = s.store.ListWebhookSubscriptions(r.Context())
	} else {
		subs, err = s.store.ListWebhookSubscriptionsByOwner(r.Context(), ActorOf(r.Context()).ID)
	}
	if err != nil {
		s.logger.Error("list webhook subscriptions", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to list webhook subscriptions")
		return
	}
	if subs == nil {
		subs = []*models.WebhookSubscription{}
	}
	writeJSON(w, http.StatusOK, subs)
}

func (s *Server) handleGetWebhookSubscription(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.loadOwnedWebhookSub(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (s *Server) handleCreateWebhookSubscription(w http.ResponseWriter, r *http.Request) {
	var req webhookSubRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := config.ValidateWebhookURL("url", req.URL, req.AllowPrivate); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Secret != nil && *req.Secret != "" && s.master == nil {
		writeError(w, http.StatusServiceUnavailable, "signing a webhook requires NEBULA_MGMT_MASTER_KEY to be configured")
		return
	}

	now := time.Now()
	sub := &models.WebhookSubscription{
		ID:              uuid.New().String(),
		OwnerOperatorID: ActorOf(r.Context()).ID,
		URL:             req.URL,
		Events:          req.Events,
		Active:          req.Active == nil || *req.Active,
		AllowPrivate:    req.AllowPrivate,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if req.Secret != nil && *req.Secret != "" {
		if err := s.sealWebhookSecret(sub, *req.Secret); err != nil {
			s.logger.Error("seal webhook secret", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to encrypt webhook secret")
			return
		}
	}
	if err := s.store.CreateWebhookSubscription(r.Context(), sub); err != nil {
		s.logger.Error("create webhook subscription", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to create webhook subscription")
		return
	}
	sub.HasSecret = len(sub.EncryptedSecret) > 0
	s.recordAuditAction(r.Context(), auditWebhookSubCreate, sub.ID, sub.URL)
	writeJSON(w, http.StatusCreated, sub)
}

func (s *Server) handleUpdateWebhookSubscription(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.loadOwnedWebhookSub(w, r)
	if !ok {
		return
	}
	var req webhookSubRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.URL == "" {
		req.URL = sub.URL
	}
	if err := config.ValidateWebhookURL("url", req.URL, req.AllowPrivate); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	sub.URL = req.URL
	sub.Events = req.Events
	sub.AllowPrivate = req.AllowPrivate
	if req.Active != nil {
		sub.Active = *req.Active
	}
	switch {
	case req.Secret == nil: // keep existing secret
	case *req.Secret == "": // clear secret
		sub.EncryptedSecretDEK, sub.NonceDEK, sub.EncryptedSecret, sub.NonceSecret = nil, nil, nil, nil
	default: // replace secret
		if s.master == nil {
			writeError(w, http.StatusServiceUnavailable, "signing a webhook requires NEBULA_MGMT_MASTER_KEY to be configured")
			return
		}
		if err := s.sealWebhookSecret(sub, *req.Secret); err != nil {
			s.logger.Error("seal webhook secret", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to encrypt webhook secret")
			return
		}
	}
	if err := s.store.UpdateWebhookSubscription(r.Context(), sub); err != nil {
		s.logger.Error("update webhook subscription", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update webhook subscription")
		return
	}
	sub.HasSecret = len(sub.EncryptedSecret) > 0
	s.recordAuditAction(r.Context(), auditWebhookSubUpdate, sub.ID, sub.URL)
	writeJSON(w, http.StatusOK, sub)
}

func (s *Server) handleDeleteWebhookSubscription(w http.ResponseWriter, r *http.Request) {
	sub, ok := s.loadOwnedWebhookSub(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteWebhookSubscription(r.Context(), sub.ID); err != nil {
		s.logger.Error("delete webhook subscription", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to delete webhook subscription")
		return
	}
	s.recordAuditAction(r.Context(), auditWebhookSubDelete, sub.ID, "")
	w.WriteHeader(http.StatusNoContent)
}

// loadOwnedWebhookSub loads the {id} subscription and enforces ownership,
// writing the error response and returning ok=false on any failure.
func (s *Server) loadOwnedWebhookSub(w http.ResponseWriter, r *http.Request) (*models.WebhookSubscription, bool) {
	id := chi.URLParam(r, "id")
	sub, err := s.store.GetWebhookSubscription(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "webhook subscription not found")
		return nil, false
	}
	if err != nil {
		s.logger.Error("get webhook subscription", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load webhook subscription")
		return nil, false
	}
	if !s.canAccessWebhookSub(r, sub) {
		writeError(w, http.StatusForbidden, "you do not own this webhook subscription")
		return nil, false
	}
	return sub, true
}

// sealWebhookSecret envelope-encrypts the secret under the master key, binding
// the subscription id as AAD (mirrors the CA key envelope).
func (s *Server) sealWebhookSecret(sub *models.WebhookSubscription, secret string) error {
	plaintext := []byte(secret)
	defer keystore.Zeroize(plaintext)
	dek, wrappedDEK, err := s.master.GenerateDEK([]byte(sub.ID))
	if err != nil {
		return err
	}
	defer keystore.Zeroize(dek)
	blob, err := keystore.SealWithDEK(dek, plaintext, []byte(sub.ID))
	if err != nil {
		return err
	}
	sub.EncryptedSecretDEK = wrappedDEK.Ciphertext
	sub.NonceDEK = wrappedDEK.Nonce
	sub.EncryptedSecret = blob.Ciphertext
	sub.NonceSecret = blob.Nonce
	return nil
}
