package web

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
)

// settingsView is the view-model the settings template renders. Each
// field carries both the current value and a "source" tag so admins can
// see whether a value comes from the database or the YAML defaults.
type settingsView struct {
	EnforceTOTP             bool
	AllowSelfRegistration   bool
	PasswordMinLength       int
	PasswordRequireClasses  int
	PasswordBlockCommon     bool
	PasswordBlockUsername   bool
	LogLevel                string
	OIDCEnabled             bool
	Saved                   bool
	Error                   string
}

func (w *Web) currentSettings(ctx context.Context) settingsView {
	return settingsView{
		EnforceTOTP:            enforceTOTPEnabled(ctx, w.store),
		AllowSelfRegistration:  boolSetting(ctx, w.store, SettingAllowSelfRegistration, w.allowSelfRegistration),
		PasswordMinLength:      intSetting(ctx, w.store, SettingPasswordMinLength, w.passwordPolicy.MinLength),
		PasswordRequireClasses: intSetting(ctx, w.store, SettingPasswordRequireClasses, w.passwordPolicy.RequireClasses),
		PasswordBlockCommon:    boolSetting(ctx, w.store, SettingPasswordBlockCommon, w.passwordPolicy.BlockCommon),
		PasswordBlockUsername:  boolSetting(ctx, w.store, SettingPasswordBlockUsername, w.passwordPolicy.BlockUsername),
		LogLevel:               stringSetting(ctx, w.store, SettingLogLevel, "info"),
		OIDCEnabled:            w.oidc.Enabled(),
	}
}

func (w *Web) handleSettingsPage(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil || op.Role != "admin" {
		http.Error(rw, "admin role required", http.StatusForbidden)
		return
	}
	view := w.currentSettings(r.Context())
	w.renderForRequest(rw, r, "settings.html", map[string]any{
		"Active":   "settings",
		"Settings": view,
	})
}

// handleSettingsSave persists every boolean / int / string knob the
// settings form exposed. Each diff against the previous value emits a
// settings.update audit entry so admins can audit who flipped what.
func (w *Web) handleSettingsSave(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil || op.Role != "admin" {
		http.Error(rw, "admin role required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "invalid form", http.StatusBadRequest)
		return
	}
	before := w.currentSettings(r.Context())

	type knob struct {
		key   string
		val   string
		human string
	}
	knobs := []knob{
		{SettingEnforceTOTP, boolFromForm(r, "enforce_2fa"), "enforce_2fa"},
		{SettingAllowSelfRegistration, boolFromForm(r, "allow_self_registration"), "allow_self_registration"},
		{SettingPasswordBlockCommon, boolFromForm(r, "password_block_common"), "password_block_common"},
		{SettingPasswordBlockUsername, boolFromForm(r, "password_block_username"), "password_block_username"},
	}
	for _, k := range knobs {
		if err := w.store.SetServerSetting(r.Context(), k.key, k.val); err != nil {
			w.renderSettingsError(rw, r, fmt.Sprintf("failed to save %s: %v", k.human, err))
			return
		}
	}

	if v := r.FormValue("password_min_length"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 256 {
			_ = w.store.SetServerSetting(r.Context(), SettingPasswordMinLength, strconv.Itoa(n))
		}
	}
	if v := r.FormValue("password_require_classes"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 4 {
			_ = w.store.SetServerSetting(r.Context(), SettingPasswordRequireClasses, strconv.Itoa(n))
		}
	}
	if v := r.FormValue("log_level"); v != "" {
		switch v {
		case "debug", "info", "warn", "error":
			_ = w.store.SetServerSetting(r.Context(), SettingLogLevel, v)
		}
	}

	// One audit-log line summarising the change set — easier to grep
	// than one per knob and still captures who pressed Save.
	after := w.currentSettings(r.Context())
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "settings.update", "settings",
		fmt.Sprintf("before=%+v after=%+v", before, after))

	view := after
	view.Saved = true
	w.renderForRequest(rw, r, "settings.html", map[string]any{
		"Active":   "settings",
		"Settings": view,
	})
}

func (w *Web) renderSettingsError(rw http.ResponseWriter, r *http.Request, msg string) {
	v := w.currentSettings(r.Context())
	v.Error = msg
	w.renderForRequest(rw, r, "settings.html", map[string]any{
		"Active":   "settings",
		"Settings": v,
	})
}

// boolFromForm normalises a checkbox to "true" / "false". HTML
// checkboxes only send a value when ticked, so absent ⇒ false.
func boolFromForm(r *http.Request, name string) string {
	if r.FormValue(name) == "" {
		return "false"
	}
	return "true"
}
