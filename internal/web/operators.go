package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// requireAdmin gates a route group to admins only — non-admin sessions
// get a 403. Sits *after* requireAuth so an unauthenticated user
// already redirects to /ui/login.
func (w *Web) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		op := w.session.CurrentOperator(r)
		if op == nil || op.Role != "admin" {
			http.Error(rw, "admin role required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (w *Web) handleOperatorsList(rw http.ResponseWriter, r *http.Request) {
	ops, err := w.store.ListOperators(r.Context())
	if err != nil {
		w.logger.Error("list operators", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.renderForRequest(rw, r, "operators_list.html", map[string]any{
		"Active":    "operators",
		"Operators": ops,
	})
}

func (w *Web) handleOperatorNewPage(rw http.ResponseWriter, r *http.Request) {
	w.renderForRequest(rw, r, "operator_new.html", map[string]any{
		"Active": "operators",
		"Error":  "",
	})
}

func (w *Web) handleOperatorCreate(rw http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.FormValue("username"))
	displayName := strings.TrimSpace(r.FormValue("display_name"))
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	role := strings.TrimSpace(r.FormValue("role"))
	if role == "" {
		role = "user"
	}

	if username == "" || password == "" {
		w.renderForRequest(rw, r, "operator_new.html", map[string]any{
			"Active": "operators",
			"Error":  "Username and password are required",
		})
		return
	}
	if password != confirm {
		w.renderForRequest(rw, r, "operator_new.html", map[string]any{
			"Active": "operators",
			"Error":  "Password confirmation does not match",
		})
		return
	}
	if err := w.passwordPolicy.Validate(password, strings.ToLower(username)); err != nil {
		w.renderForRequest(rw, r, "operator_new.html", map[string]any{
			"Active": "operators",
			"Error":  err.Error(),
		})
		return
	}
	if _, err := w.store.GetOperatorByUsername(r.Context(), username); err == nil {
		w.renderForRequest(rw, r, "operator_new.html", map[string]any{
			"Active": "operators",
			"Error":  "Username already taken",
		})
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		w.logger.Error("operator lookup", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.logger.Error("hash password", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	op := &models.Operator{
		ID:           uuid.New().String(),
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: string(hash),
		Status:       models.OperatorStatusActive,
		Role:         role,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := w.store.CreateOperator(r.Context(), op); err != nil {
		w.logger.Error("create operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.create", op.ID, op.Username)

	http.Redirect(rw, r, "/ui/operators/"+op.ID, http.StatusSeeOther)
}

func (w *Web) handleOperatorDetail(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	op, err := w.store.GetOperator(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(rw, "operator not found", http.StatusNotFound)
		return
	}
	if err != nil {
		w.logger.Error("get operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	keys, err := w.store.ListOperatorAPIKeys(r.Context(), id)
	if err != nil {
		w.logger.Error("list api keys", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.renderForRequest(rw, r, "operator_detail.html", map[string]any{
		"Active":     "operators",
		"Operator":   op,
		"APIKeys":    keys,
		"NewAPIKey":  r.URL.Query().Get("new_key"),
		"KeyName":    r.URL.Query().Get("key_name"),
	})
}

func (w *Web) handleOperatorDisable(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := w.store.DisableOperator(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		w.logger.Error("disable operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.disable", id, "")
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther)
}

func (w *Web) handleOperatorEnable(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := w.store.EnableOperator(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		w.logger.Error("enable operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.enable", id, "")
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther)
}

func (w *Web) handleOperatorResetPassword(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	op, err := w.store.GetOperator(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(rw, "operator not found", http.StatusNotFound)
		return
	}
	if err != nil {
		w.logger.Error("get operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	password := r.FormValue("password")
	if err := w.passwordPolicy.Validate(password, strings.ToLower(op.Username)); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.logger.Error("hash password", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if err := w.store.UpdateOperatorPassword(r.Context(), id, string(hash)); err != nil {
		w.logger.Error("update password", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.reset_password", id, op.Username)
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther)
}

func (w *Web) handleOperatorCreateAPIKey(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := w.store.GetOperator(r.Context(), id); err != nil {
		http.Error(rw, "operator not found", http.StatusNotFound)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "ui-created"
	}
	raw, err := newAPIKeyToken()
	if err != nil {
		w.logger.Error("generate api key", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	key := &models.OperatorAPIKey{
		ID:         uuid.New().String(),
		OperatorID: id,
		Name:       name,
		KeyHash:    hash,
		CreatedAt:  time.Now(),
	}
	if err := w.store.CreateOperatorAPIKey(r.Context(), key); err != nil {
		w.logger.Error("create api key", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.api_key.create", id, key.ID)
	http.Redirect(rw, r, "/ui/operators/"+id+"?new_key="+raw+"&key_name="+name, http.StatusSeeOther)
}

func (w *Web) handleOperatorRevokeAPIKey(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	kid := chi.URLParam(r, "kid")
	err := w.store.RevokeOperatorAPIKey(r.Context(), kid)
	switch {
	case err == nil:
		actor := actorUsername(r, w.session)
		_ = w.store.AddAuditEntry(r.Context(), actor, "operator.api_key.revoke", id, kid)
	case errors.Is(err, store.ErrNotFound):
		// Already revoked (DisableOperator auto-revokes every key in the
		// same transaction). UI stays idempotent — just redirect back.
	default:
		w.logger.Error("revoke api key", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther)
}

// newAPIKeyToken returns the plaintext key shown once to the operator.
// 32 random bytes hex-encoded — 64 chars, indistinguishable from the
// CLI-generated token shape.
func newAPIKeyToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func actorUsername(r *http.Request, sm *SessionManager) string {
	if op := sm.CurrentOperator(r); op != nil {
		return op.Username
	}
	return "anonymous"
}
