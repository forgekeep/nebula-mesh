package api

import (
	"encoding/json"
	"net/http"
)

// settingEnforceTOTP duplicates the web package's exported key name so
// the API handler doesn't pull web in. Keep these literally identical
// — the value is the contract.
const settingEnforceTOTP = "enforce_2fa"

type settingsRequest struct {
	EnforceTOTP *bool `json:"enforce_2fa,omitempty"`
}

type settingsResponse struct {
	EnforceTOTP bool `json:"enforce_2fa"`
}

// handleGetSettings returns the current admin-tunable server settings.
// Admin-only because exposing the surface to non-admins gives them a
// view of the deployment's security posture.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}
	v, _ := s.store.GetServerSetting(r.Context(), settingEnforceTOTP)
	writeJSON(w, http.StatusOK, settingsResponse{EnforceTOTP: v == "true"})
}

// handlePatchSettings updates one or more admin-tunable settings.
// Currently exposes only enforce_2fa; will grow with the rest of #47.
func (s *Server) handlePatchSettings(w http.ResponseWriter, r *http.Request) {
	if !actorIsAdmin(r.Context()) {
		writeError(w, http.StatusForbidden, "admin role required")
		return
	}
	var req settingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.EnforceTOTP != nil {
		val := "false"
		if *req.EnforceTOTP {
			val = "true"
		}
		if err := s.store.SetServerSetting(r.Context(), settingEnforceTOTP, val); err != nil {
			s.logger.Error("set enforce_2fa", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to update setting")
			return
		}
		s.recordAuditAction(r.Context(), auditSettingsEnforce2FA, settingEnforceTOTP, val)
	}
	v, _ := s.store.GetServerSetting(r.Context(), settingEnforceTOTP)
	writeJSON(w, http.StatusOK, settingsResponse{EnforceTOTP: v == "true"})
}
