package web

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
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
	form := newOperatorFormState(r)
	w.renderForRequest(rw, r, "operator_new.html", map[string]any{
		"Active":       "operators",
		"Form":         form,
		"PasswordHint": w.passwordPolicy.HumanHint(),
	})
}

func (w *Web) handleOperatorCreate(rw http.ResponseWriter, r *http.Request) {
	form := newOperatorFormState(r)
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	hint := w.passwordPolicy.HumanHint()

	// Check required fields: username and password.
	if form.Username == "" {
		form.Errors["username"] = "Required"
	}
	if password == "" {
		form.Errors["password"] = "Required"
	}
	// The form's select only offers the known roles, but the value is
	// client-controlled — reject anything else here rather than surfacing
	// the store's error as a 500.
	if !models.ValidOperatorRole(form.Role) {
		form.Errors["role"] = "Must be admin or user"
	}

	// If any required fields are missing, render error and return.
	if len(form.Errors) > 0 {
		w.renderOperatorNewError(rw, r, form, hint)
		return
	}

	// Check password confirmation matches.
	if password != confirm {
		form.Errors["password_confirm"] = "Does not match"
		w.renderOperatorNewError(rw, r, form, hint)
		return
	}

	// Validate password policy.
	if err := w.passwordPolicy.Validate(password, strings.ToLower(form.Username)); err != nil {
		form.Errors["password"] = err.Error()
		w.renderOperatorNewError(rw, r, form, hint)
		return
	}

	// Check username availability.
	if _, err := w.store.GetOperatorByUsername(r.Context(), form.Username); err == nil {
		form.Errors["username"] = "Username already taken"
		w.renderOperatorNewError(rw, r, form, hint)
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		w.logger.Error("operator lookup", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	// Hash password and create operator.
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.logger.Error("hash password", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	op := &models.Operator{
		ID:           uuid.NewV4().String(),
		Username:     form.Username,
		DisplayName:  form.DisplayName,
		PasswordHash: string(hash),
		Status:       models.OperatorStatusActive,
		Role:         form.Role,
		AuthProvider: models.OperatorAuthLocal,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := w.store.CreateOperator(r.Context(), op); err != nil {
		w.logger.Error("create operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	// Audit entry only written after successful CreateOperator.
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.create", op.ID, op.Username)

	if err := w.provisionDefaultCA(r.Context(), op); err != nil {
		w.logger.Warn("auto-provision default CA on operator create failed", "operator", op.Username, "error", err)
	}

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
	// GHSA-9pg3-25fq-p6cc: pop the one-shot API-key flash set on the prior
	// POST instead of trusting query parameters. Empty strings on miss /
	// expiry / refresh — template treats those as "nothing to show".
	rawKey, keyName, _ := w.popAPIKeyFlash(r)
	w.renderForRequest(rw, r, "operator_detail.html", map[string]any{
		"Active":    "operators",
		"Operator":  op,
		"APIKeys":   keys,
		"NewAPIKey": rawKey,
		"KeyName":   keyName,
	})
}

func (w *Web) handleOperatorDisable(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := w.store.GetOperator(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(rw, "operator not found", http.StatusNotFound)
			return
		}
		w.logger.Error("get operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if err := w.store.DisableOperator(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		w.logger.Error("disable operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.disable", id, "")
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther) // #nosec G710 -- same-origin redirect: hardcoded /ui/operators/ prefix ensures Location stays on the current host regardless of id contents
}

func (w *Web) handleOperatorEnable(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := w.store.GetOperator(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(rw, "operator not found", http.StatusNotFound)
			return
		}
		w.logger.Error("get operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if err := w.store.EnableOperator(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		w.logger.Error("enable operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.enable", id, "")
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther) // #nosec G710 -- same-origin redirect: hardcoded /ui/operators/ prefix ensures Location stays on the current host regardless of id contents
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
	// Terminate the operator's existing sessions so a reset meant to lock out
	// a compromised credential actually revokes access (CWE-613), mirroring the
	// cascade in DisableOperator. The password is already changed; log on
	// failure but do not abort.
	if err := w.store.DeleteOperatorSessionsByOperator(r.Context(), id); err != nil {
		w.logger.Error("invalidate sessions on password reset", "error", err)
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.reset_password", id, op.Username)
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther) // #nosec G710 -- same-origin redirect: hardcoded /ui/operators/ prefix ensures Location stays on the current host regardless of id contents
}

func (w *Web) handleOperatorCreateAPIKey(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := w.store.GetOperator(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(rw, "operator not found", http.StatusNotFound)
			return
		}
		w.logger.Error("get operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
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
	key := &models.OperatorAPIKey{
		ID:         uuid.NewV4().String(),
		OperatorID: id,
		Name:       name,
		CreatedAt:  time.Now(),
	}
	if err := w.store.CreateOperatorAPIKey(r.Context(), key, raw); err != nil {
		w.logger.Error("create api key", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.api_key.create", id, key.ID)
	// GHSA-9pg3-25fq-p6cc: stash the raw key in a one-shot server-side
	// flash keyed by the session cookie instead of appending it to the
	// redirect Location. The detail handler pops + clears on render.
	w.setAPIKeyFlash(r, raw, name)
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther) // #nosec G710 -- same-origin redirect: hardcoded /ui/operators/ prefix ensures Location stays on the current host regardless of id contents
}

func (w *Web) handleOperatorRevokeAPIKey(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	kid := chi.URLParam(r, "kid")
	if _, err := w.store.GetOperator(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(rw, "operator not found", http.StatusNotFound)
			return
		}
		w.logger.Error("get operator", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	// Verify the API key belongs to this operator before revoking.
	// Without this, an admin could revoke any operator's API key while
	// the audit row records the URL-supplied operator id instead of the
	// key's real owner, breaking forensic correlation.
	key, err := w.store.GetOperatorAPIKey(r.Context(), kid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Error(rw, "api key not found", http.StatusNotFound)
			return
		}
		w.logger.Error("get api key", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if key.OperatorID != id {
		http.Error(rw, "api key not found", http.StatusNotFound)
		return
	}
	if key.RevokedAt != nil {
		// Already revoked (DisableOperator auto-revokes every key in the
		// same transaction). UI stays idempotent — skip the no-op UPDATE
		// and the audit row.
		http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther) // #nosec G710 -- same-origin redirect: hardcoded /ui/operators/ prefix ensures Location stays on the current host regardless of id contents
		return
	}
	if err := w.store.RevokeOperatorAPIKey(r.Context(), kid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Concurrent revoke (another admin in another session, or a
			// DisableOperator cascade) won the CAS between the
			// GetOperatorAPIKey snapshot above and this UPDATE. Already
			// revoked — mirror the RevokedAt != nil idempotent branch
			// above (303 redirect, no audit row, since this actor's call
			// did not cause the state change).
			http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther) // #nosec G710 -- same-origin redirect: hardcoded /ui/operators/ prefix ensures Location stays on the current host regardless of id contents
			return
		}
		w.logger.Error("revoke api key", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	actor := actorUsername(r, w.session)
	_ = w.store.AddAuditEntry(r.Context(), actor, "operator.api_key.revoke", id, kid)
	http.Redirect(rw, r, "/ui/operators/"+id, http.StatusSeeOther) // #nosec G710 -- same-origin redirect: hardcoded /ui/operators/ prefix ensures Location stays on the current host regardless of id contents
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
