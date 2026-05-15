package web

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/mobilebundle"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// isEnrolmentPath reports whether a path is one of the routes a
// gated-into-2FA operator is still allowed to hit. Keeps the enrolment
// page reachable while everything else 303s back to the gate.
func isEnrolmentPath(path string) bool {
	switch path {
	case "/ui/2fa/required", "/ui/2fa/setup", "/ui/2fa/enable", "/ui/logout":
		return true
	}
	return false
}

// Login label constants mirror those exported by the API server's metrics
// layer (api.ResultOK / api.LoginFactorPassword / …). They are duplicated
// here, not imported, to keep this package free of an api ↔ web edge — the
// api package's metrics layer pre-seeds the same strings so the canonical
// values stay aligned at the point of registration.
const (
	loginResultOK       = "ok"
	loginResultDenied   = "denied"
	loginResultError    = "error"
	loginFactorPassword = "password"
	loginFactorTOTP     = "totp"
	loginFactorRecovery = "recovery"
)

// requireAuth middleware redirects to login if not authenticated. When
// admin-enforced 2FA is on (server_settings.enforce_2fa = "true"), any
// authenticated local operator without TOTP enrolled is redirected to
// /ui/2fa/required and cannot reach any other /ui/* route until they
// complete enrolment. OIDC operators are exempt — their second factor
// is the IdP's job.
func (w *Web) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !w.session.IsAuthenticated(r) {
			http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
			return
		}
		if op := w.session.CurrentOperator(r); op != nil &&
			!op.TOTPEnabled &&
			op.AuthProvider != models.OperatorAuthOIDC &&
			enforceTOTPEnabled(r.Context(), w.store) &&
			!isEnrolmentPath(r.URL.Path) {
			http.Redirect(rw, r, "/ui/2fa/required", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (w *Web) handleLoginPage(rw http.ResponseWriter, r *http.Request) {
	w.renderForRequest(rw, r, "login.html", map[string]any{
		"Error":                "",
		"OIDCEnabled":          w.oidc.Enabled(),
		"AllowSelfRegistration": w.allowSelfRegistrationEffective(r.Context()),
	})
}

func (w *Web) handleLogin(rw http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		username = "admin"
	}
	password := r.FormValue("password")
	result, ok, err := w.session.Login(rw, r, username, password)
	if err != nil {
		w.recordLogin(loginResultError, loginFactorPassword)
		w.logger.Error("login", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		w.recordLogin(loginResultDenied, loginFactorPassword)
		w.renderForRequest(rw, r, "login.html", map[string]any{
			"Error":                 "Invalid username or password",
			"OIDCEnabled":           w.oidc.Enabled(),
			"AllowSelfRegistration": w.allowSelfRegistrationEffective(r.Context()),
		})
		return
	}
	if result.NeedsTOTP {
		w.recordLogin(loginResultOK, loginFactorPassword)
		http.Redirect(rw, r, "/ui/login/totp", http.StatusSeeOther)
		return
	}
	w.recordLogin(loginResultOK, loginFactorPassword)
	http.Redirect(rw, r, "/ui/", http.StatusSeeOther)
}

func (w *Web) handleTOTPLoginPage(rw http.ResponseWriter, r *http.Request) {
	if op := w.session.PendingOperator(r); op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	w.renderForRequest(rw, r, "login_totp.html", map[string]any{"Error": ""})
}

func (w *Web) handleTOTPLogin(rw http.ResponseWriter, r *http.Request) {
	op := w.session.PendingOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	recovery := strings.TrimSpace(r.FormValue("recovery_code"))

	ok := false
	usedRecovery := false
	if code != "" && verifyTOTP(op.TOTPSecret, code) {
		ok = true
	} else if recovery != "" {
		if err := w.store.ConsumeOperatorRecoveryCode(r.Context(), op.ID, hashRecoveryCode(recovery)); err == nil {
			ok = true
			usedRecovery = true
		}
	}

	if !ok {
		factor := loginFactorTOTP
		if recovery != "" {
			factor = loginFactorRecovery
		}
		w.recordLogin(loginResultDenied, factor)
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.failed", op.ID, "")
		w.renderForRequest(rw, r, "login_totp.html", map[string]any{"Error": "Invalid TOTP code"})
		return
	}
	if err := w.session.CompleteTwoFactor(rw, r, op.ID); err != nil {
		w.recordLogin(loginResultError, loginFactorTOTP)
		w.logger.Error("complete 2fa", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	factor := loginFactorTOTP
	details := "totp"
	if usedRecovery {
		factor = loginFactorRecovery
		details = "recovery"
	}
	w.recordLogin(loginResultOK, factor)
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.verified", op.ID, details)
	http.Redirect(rw, r, "/ui/", http.StatusSeeOther)
}

func (w *Web) handleLogout(rw http.ResponseWriter, r *http.Request) {
	w.session.Logout(rw, r)
	http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
}

// --- Self-registration ---

func (w *Web) handleRegisterPage(rw http.ResponseWriter, r *http.Request) {
	if !w.allowSelfRegistrationEffective(r.Context()) {
		http.Error(rw, "self-registration is disabled", http.StatusForbidden)
		return
	}
	w.renderForRequest(rw, r, "register.html", map[string]any{"Error": ""})
}

func (w *Web) handleRegister(rw http.ResponseWriter, r *http.Request) {
	if !w.allowSelfRegistrationEffective(r.Context()) {
		http.Error(rw, "self-registration is disabled", http.StatusForbidden)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	displayName := strings.TrimSpace(r.FormValue("display_name"))

	if username == "" || password == "" {
		w.renderForRequest(rw, r, "register.html", map[string]any{"Error": "Username and password are required"})
		return
	}
	if err := w.passwordPolicy.Validate(password, strings.ToLower(username)); err != nil {
		w.renderForRequest(rw, r, "register.html", map[string]any{"Error": err.Error()})
		return
	}
	if password != confirm {
		w.renderForRequest(rw, r, "register.html", map[string]any{"Error": "Password confirmation does not match"})
		return
	}

	if _, err := w.store.GetOperatorByUsername(r.Context(), username); err == nil {
		w.renderForRequest(rw, r, "register.html", map[string]any{"Error": "Username already taken"})
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		w.logger.Error("register: lookup", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.logger.Error("register: hash", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	op := &models.Operator{
		ID:           uuid.New().String(),
		Username:     username,
		DisplayName:  displayName,
		PasswordHash: string(hash),
		Role:         "user",
	}
	if err := w.store.CreateOperator(r.Context(), op); err != nil {
		w.logger.Error("register: create", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	_ = w.store.AddAuditEntry(r.Context(), username, "operator.self_register", op.ID, "")
	if err := w.provisionDefaultCA(r.Context(), op); err != nil {
		w.logger.Warn("auto-provision default CA on register failed", "operator", op.Username, "error", err)
	}
	http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
}

// --- Profile ---

func (w *Web) handleProfilePage(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	cas, err := w.store.ListCAsByOwner(r.Context(), op.ID)
	if err != nil {
		w.logger.Error("list cas for profile", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	// Pre-compute IsExpiringSoon for each CA using pki.ShouldRenew threshold.
	caViews := make([]*caView, len(cas))
	for i, ca := range cas {
		caViews[i] = &caView{
			CA:             ca,
			IsExpiringSoon: pki.ShouldRenew(ca.NotBefore, ca.NotAfter),
		}
	}
	w.renderForRequest(rw, r, "profile.html", map[string]any{
		"Active":   "profile",
		"Operator": op,
		"CAs":      caViews,
	})
}

// --- 2FA management ---

func (w *Web) handleTwoFAPage(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	w.renderForRequest(rw, r, "twofa.html", map[string]any{
		"Active":      "2fa",
		"Operator":    op,
		"TOTPEnabled": op.TOTPEnabled,
		"Setup":       nil,
		"NewCodes":    nil,
		"Error":       "",
		"Enforced":    enforceTOTPEnabled(r.Context(), w.store),
	})
}

// handleTwoFARequired is the forced-enrolment gate. Identical to the
// regular /ui/2fa page except (a) it is reachable from requireAuth's
// redirect path even when admin-enforced 2FA is on, and (b) the
// template renders without the sidebar so the operator can't navigate
// away. The actual TOTP setup / verification happens on
// /ui/2fa/setup and /ui/2fa/enable as usual.
func (w *Web) handleTwoFARequired(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	if op.TOTPEnabled {
		http.Redirect(rw, r, "/ui/", http.StatusSeeOther)
		return
	}
	w.renderForRequest(rw, r, "twofa.html", map[string]any{
		"Active":      "2fa",
		"Operator":    op,
		"TOTPEnabled": false,
		"Setup":       nil,
		"NewCodes":    nil,
		"Error":       "",
		"Enforced":    true,
		"Required":    true,
	})
}

type totpSetup struct {
	OTPURL       string
	SecretGroup  string
	SecretRaw    string
}

func (w *Web) handleTwoFASetup(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	if op.TOTPEnabled {
		http.Redirect(rw, r, "/ui/2fa", http.StatusSeeOther)
		return
	}
	url, secret, err := generateTOTPSecret(op.Username)
	if err != nil {
		w.logger.Error("generate totp", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	// Save the secret but keep totp_enabled=false until verification.
	if err := w.store.SetOperatorTOTP(r.Context(), op.ID, secret, false); err != nil {
		w.logger.Error("save pending totp", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	w.renderForRequest(rw, r, "twofa.html", map[string]any{
		"Active":      "2fa",
		"Operator":    op,
		"TOTPEnabled": false,
		"Setup": &totpSetup{
			OTPURL:      url,
			SecretGroup: encodeSecretForDisplay(secret),
			SecretRaw:   secret,
		},
		"NewCodes": nil,
		"Error":    "",
	})
}

func (w *Web) handleTwoFAEnable(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	if op.TOTPSecret == "" {
		http.Redirect(rw, r, "/ui/2fa", http.StatusSeeOther)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if !verifyTOTP(op.TOTPSecret, code) {
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.enable_failed", op.ID, "")
		w.renderForRequest(rw, r, "twofa.html", map[string]any{
			"Active":      "2fa",
			"Operator":    op,
			"TOTPEnabled": false,
			"Setup": &totpSetup{
				SecretGroup: encodeSecretForDisplay(op.TOTPSecret),
				SecretRaw:   op.TOTPSecret,
			},
			"Error": "Invalid code; try again",
		})
		return
	}
	if err := w.store.SetOperatorTOTP(r.Context(), op.ID, op.TOTPSecret, true); err != nil {
		w.logger.Error("enable totp", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	codes, hashes, err := generateRecoveryCodes(totpRecoveryCodeCount)
	if err != nil {
		w.logger.Error("generate recovery codes", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if err := w.store.ReplaceOperatorRecoveryCodes(r.Context(), op.ID, hashes); err != nil {
		w.logger.Error("save recovery codes", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.enabled", op.ID, "")
	if enforceTOTPEnabled(r.Context(), w.store) {
		// Track that this operator completed forced enrolment so an
		// admin can audit the rollout.
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.enforced.enrolled", op.ID, "")
	}
	w.renderForRequest(rw, r, "twofa.html", map[string]any{
		"Active":      "2fa",
		"Operator":    op,
		"TOTPEnabled": true,
		"NewCodes":    codes,
		"Error":       "",
	})
}

func (w *Web) handleTwoFADisable(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	if enforceTOTPEnabled(r.Context(), w.store) {
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.enforced.disable_blocked", op.ID, "")
		http.Error(rw, "Disabling 2FA is not allowed — admin-enforced 2FA is active. Contact your administrator.", http.StatusForbidden)
		return
	}
	password := r.FormValue("password")
	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(password)); err != nil {
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.disable_failed", op.ID, "")
		w.renderForRequest(rw, r, "twofa.html", map[string]any{
			"Active":      "2fa",
			"Operator":    op,
			"TOTPEnabled": op.TOTPEnabled,
			"Error":       "Password does not match",
		})
		return
	}
	if err := w.store.SetOperatorTOTP(r.Context(), op.ID, "", false); err != nil {
		w.logger.Error("disable totp", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.disabled", op.ID, "")
	http.Redirect(rw, r, "/ui/2fa", http.StatusSeeOther)
}

func (w *Web) handleTwoFARegenCodes(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	if !op.TOTPEnabled {
		http.Redirect(rw, r, "/ui/2fa", http.StatusSeeOther)
		return
	}
	codes, hashes, err := generateRecoveryCodes(totpRecoveryCodeCount)
	if err != nil {
		w.logger.Error("generate recovery codes", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if err := w.store.ReplaceOperatorRecoveryCodes(r.Context(), op.ID, hashes); err != nil {
		w.logger.Error("save recovery codes", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.regen_codes", op.ID, "")
	w.renderForRequest(rw, r, "twofa.html", map[string]any{
		"Active":      "2fa",
		"Operator":    op,
		"TOTPEnabled": true,
		"NewCodes":    codes,
		"Error":       "",
	})
}

func (w *Web) handleFavicon(rw http.ResponseWriter, _ *http.Request) {
	data, err := staticFS.ReadFile("static/favicon.svg")
	if err != nil {
		w.logger.Error("read favicon", "error", err)
		http.Error(rw, "favicon not found", http.StatusNotFound)
		return
	}
	rw.Header().Set("Content-Type", "image/svg+xml")
	rw.Header().Set("Cache-Control", "public, max-age=86400")
	if _, err := rw.Write(data); err != nil {
		w.logger.Error("write favicon", "error", err)
	}
}

// --- Dashboard ---

// hostView is a view-model that augments models.Host with the resolved
// human-readable network name and the computed "online" flag. Embedding
// keeps every existing template field access (.ID, .Name, .NebulaIPs, …)
// working unchanged.
type hostView struct {
	*models.Host
	NetworkName string
	Online      bool
}

// buildHostViews resolves NetworkID → Network.Name for each host and
// stamps the "online" flag (last_seen_at within hostOnlineThreshold). If
// the host's network is not present in networks, NetworkName is left
// empty so the template can fall back to displaying the UUID.
func buildHostViews(hosts []*models.Host, networks []*models.Network) []hostView {
	if len(hosts) == 0 {
		return nil
	}
	idx := make(map[string]string, len(networks))
	for _, n := range networks {
		idx[n.ID] = n.Name
	}
	now := time.Now()
	out := make([]hostView, len(hosts))
	for i, h := range hosts {
		out[i] = hostView{
			Host:        h,
			NetworkName: idx[h.NetworkID],
			Online:      isHostOnline(h.LastSeenAt, hostOnlineThreshold, now),
		}
	}
	return out
}

type dashboardStats struct {
	TotalHosts    int
	EnrolledHosts int
	PendingHosts  int
	BlockedHosts  int
	Networks      int
	ExpiringCerts int
}

func computeStats(hosts []*models.Host, networkCount int) dashboardStats {
	stats := dashboardStats{
		TotalHosts: len(hosts),
		Networks:   networkCount,
	}
	for _, h := range hosts {
		switch h.Status {
		case models.HostStatusEnrolled:
			stats.EnrolledHosts++
			if h.CertExpiresAt != nil && time.Until(*h.CertExpiresAt) < 7*24*time.Hour {
				stats.ExpiringCerts++
			}
		case models.HostStatusPending:
			stats.PendingHosts++
		case models.HostStatusBlocked:
			stats.BlockedHosts++
		}
	}
	return stats
}

func (w *Web) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks", "error", err)
		http.Error(rw, "Failed to load dashboard", http.StatusInternalServerError)
		return
	}
	hosts, err := w.store.ListHosts(r.Context(), store.HostFilter{Limit: 1000})
	if err != nil {
		w.logger.Error("list hosts", "error", err)
		http.Error(rw, "Failed to load dashboard", http.StatusInternalServerError)
		return
	}

	stats := computeStats(hosts, len(networks))

	recentHosts := hosts
	if len(recentHosts) > 10 {
		recentHosts = recentHosts[len(recentHosts)-10:]
	}

	w.renderForRequest(rw, r, "dashboard.html", map[string]any{
		"Active":      "dashboard",
		"Stats":       stats,
		"RecentHosts": buildHostViews(recentHosts, networks),
	})
}

func (w *Web) handlePartialStats(rw http.ResponseWriter, r *http.Request) {
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks", "error", err)
		http.Error(rw, "Failed to load stats", http.StatusInternalServerError)
		return
	}
	hosts, err := w.store.ListHosts(r.Context(), store.HostFilter{Limit: 1000})
	if err != nil {
		w.logger.Error("list hosts", "error", err)
		http.Error(rw, "Failed to load stats", http.StatusInternalServerError)
		return
	}
	stats := computeStats(hosts, len(networks))
	w.renderForRequest(rw, r, "stats_partial.html", map[string]any{
		"Stats": stats,
	})
}

// --- Hosts ---

func (w *Web) handleHosts(rw http.ResponseWriter, r *http.Request) {
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks", "error", err)
		http.Error(rw, "Failed to load hosts", http.StatusInternalServerError)
		return
	}
	hosts, err := w.store.ListHosts(r.Context(), store.HostFilter{Limit: 1000})
	if err != nil {
		w.logger.Error("list hosts", "error", err)
		http.Error(rw, "Failed to load hosts", http.StatusInternalServerError)
		return
	}

	w.renderForRequest(rw, r, "hosts.html", map[string]any{
		"Active": "hosts",
		"Hosts":  buildHostViews(hosts, networks),
	})
}

func (w *Web) handleHostNew(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	networks, err := w.accessibleNetworks(r.Context(), op)
	if err != nil {
		w.logger.Error("list networks for host form", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	form := hostFormState{Kind: "agent"}
	w.renderForRequest(rw, r, "host_new.html", map[string]any{
		"Active":      "hosts",
		"Networks":    networks,
		"HasNetworks": len(networks) > 0,
		"Form":        form,
		"Error":       "",
	})
}

func (w *Web) handleHostCreate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}

	form := newHostFormState(r)

	// Resolve the chosen network and check that the operator is allowed
	// to attach a host to it (issue #93). admins keep their existing
	// blanket access; users must own the CA that signs the network.
	var network *models.Network
	if networkID := form.NetworkID; networkID != "" {
		n, err := w.store.GetNetwork(r.Context(), networkID)
		if errors.Is(err, store.ErrNotFound) {
			w.renderHostNewError(rw, r, form, "network not found")
			return
		}
		if err != nil {
			w.logger.Error("get network for host create", "error", err)
			http.Error(rw, "Failed to load network", http.StatusInternalServerError)
			return
		}
		if op.Role != "admin" {
			if n.CAID == "" {
				w.renderHostNewError(rw, r, form, "this network is not tied to a CA you own — pick a network you created")
				return
			}
			ca, err := w.store.GetCA(r.Context(), n.CAID)
			if err != nil || ca.OwnerOperatorID != op.ID {
				w.renderHostNewError(rw, r, form, "this network is not tied to a CA you own — pick a network you created")
				return
			}
		}
		network = n
	}

	// Validate NebulaIPs against the network if selected
	networkID := form.NetworkID
	if len(form.NebulaIPs) > 0 && networkID != "" {
		perRowErrors := make(map[int]string)
		for i, ip := range form.NebulaIPs {
			if err := validateHostIPForNetwork(r.Context(), w.store, networkID, ip, ""); err != nil {
				perRowErrors[i] = err.Error()
			}
		}
		if len(perRowErrors) > 0 {
			form.NebulaIPErrors = perRowErrors
			w.renderHostNewError(rw, r, form, "one or more IP addresses are invalid")
			return
		}
	} else if len(form.NebulaIPs) > 0 {
		// Network not selected; just parse-check each IP
		perRowErrors := make(map[int]string)
		for i, ip := range form.NebulaIPs {
			if _, err := netip.ParseAddr(ip); err != nil {
				perRowErrors[i] = models.FriendlyAddrError("nebula_ip", ip)
			}
		}
		if len(perRowErrors) > 0 {
			form.NebulaIPErrors = perRowErrors
			w.renderHostNewError(rw, r, form, "one or more IP addresses are invalid")
			return
		}
	}

	if strings.TrimSpace(form.PublicIP) != "" {
		if _, err := netip.ParseAddr(form.PublicIP); err != nil {
			w.renderHostNewError(rw, r, form, models.FriendlyAddrError("public_ip", form.PublicIP))
			return
		}
	}

	var listenPort int
	if form.ListenPort != "" {
		var err error
		listenPort, err = strconv.Atoi(form.ListenPort)
		if err != nil {
			w.renderHostNewError(rw, r, form, "invalid listen_port: must be a number")
			return
		}
		if listenPort < 0 || listenPort > 65535 {
			w.renderHostNewError(rw, r, form, "listen_port must be between 0 and 65535")
			return
		}
	}
	role := models.HostRole(form.Role)
	if !models.ValidRole(role) {
		w.renderHostNewError(rw, r, form, "invalid role")
		return
	}
	if role == "" {
		role = models.HostRoleHost
	}
	if err := models.ValidateRoleReachability(role, form.PublicIP, listenPort); err != nil {
		w.renderHostNewError(rw, r, form, err.Error())
		return
	}

	var groups []string
	if g := strings.TrimSpace(form.Groups); g != "" {
		for _, s := range strings.Split(g, ",") {
			groups = append(groups, strings.TrimSpace(s))
		}
	}
	if groups == nil {
		groups = []string{}
	}

	advanced, err := parseAdvancedFromForm(r)
	if err != nil {
		w.renderHostNewError(rw, r, form, err.Error())
		return
	}
	if err := models.ValidateHostAdvanced(advanced); err != nil {
		w.renderHostNewError(rw, r, form, err.Error())
		return
	}

	kind := models.HostKind(form.Kind)
	if kind == "" {
		kind = models.HostKindAgent
	}
	if !models.ValidKind(kind) {
		w.renderHostNewError(rw, r, form, "invalid host kind")
		return
	}
	variant := models.HostVariant(form.Variant)
	if kind != models.HostKindMobile {
		variant = models.HostVariantNone
	}
	if !models.ValidVariant(variant) {
		w.renderHostNewError(rw, r, form, "invalid mobile variant")
		return
	}
	if err := models.ValidateMobileConstraints(kind, variant, role); err != nil {
		w.renderHostNewError(rw, r, form, err.Error())
		return
	}

	now := time.Now()
	host := &models.Host{
		ID:           uuid.New().String(),
		NetworkID:    networkID,
		CAID:         networkCAID(network),
		Name:         form.Name,
		NebulaIPs:    form.NebulaIPs,
		Groups:       groups,
		Role:         role,
		IsLighthouse: role == models.HostRoleLighthouse,
		IsRelay:      role == models.HostRoleRelay,
		PublicIP:     form.PublicIP,
		ListenPort:   listenPort,
		Status:       models.HostStatusPending,
		Kind:         kind,
		Variant:      variant,
		Advanced:     advanced,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Mobile hosts don't use the agent enrollment flow — they get a
	// self-contained YAML bundle on creation, so no enrollment token is needed.
	if kind == models.HostKindMobile {
		if err := w.store.CreateHost(r.Context(), host); err != nil {
			w.logger.Error("create mobile host", "error", err)
			http.Error(rw, "Failed to create host", http.StatusInternalServerError)
			return
		}
		w.renderMobileBundle(rw, r, host)
		return
	}

	token := &models.EnrollmentToken{
		ID:        uuid.New().String(),
		HostID:    host.ID,
		Token:     uuid.New().String(),
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := w.store.CreateHostAndToken(r.Context(), host, token); err != nil {
		w.logger.Error("create host and token", "error", err)
		http.Error(rw, "Failed to create host", http.StatusInternalServerError)
		return
	}

	w.renderForRequest(rw, r, "host_detail.html", map[string]any{
		"Active": "hosts",
		"Host":   host,
		"Token":  token.Token,
	})
}

func (w *Web) handleHostDetail(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := w.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		w.logger.Error("get host", "error", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.renderForRequest(rw, r, "host_detail.html", map[string]any{
		"Active": "hosts",
		"Host":   host,
	})
}

func (w *Web) handleHostEdit(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}

	id := chi.URLParam(r, "id")
	host, err := w.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		w.logger.Error("get host for edit", "error", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Ownership check: non-admin operators must own the CA signing the network
	if op.Role != "admin" {
		network, err := w.store.GetNetwork(r.Context(), host.NetworkID)
		if err != nil {
			w.logger.Error("get network for ownership check", "error", err)
			http.Error(rw, "Failed to load network", http.StatusInternalServerError)
			return
		}
		if network.CAID == "" {
			http.Error(rw, "Unauthorized", http.StatusForbidden)
			return
		}
		ca, err := w.store.GetCA(r.Context(), network.CAID)
		if err != nil || ca.OwnerOperatorID != op.ID {
			http.Error(rw, "Unauthorized", http.StatusForbidden)
			return
		}
	}

	// Load network for CIDR display and validation
	network, err := w.store.GetNetwork(r.Context(), host.NetworkID)
	if err != nil {
		w.logger.Error("get network for edit form", "error", err)
		http.Error(rw, "Failed to load network", http.StatusInternalServerError)
		return
	}

	w.renderForRequest(rw, r, "host_edit.html", map[string]any{
		"Active":  "hosts",
		"Host":    host,
		"Network": network,
		"Form":    hostFormStateFromHost(host),
		"Error":   "",
	})
}

func (w *Web) handleHostUpdate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}

	id := chi.URLParam(r, "id")
	host, err := w.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		w.logger.Error("get host for update", "error", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Ownership check
	if op.Role != "admin" {
		network, err := w.store.GetNetwork(r.Context(), host.NetworkID)
		if err != nil {
			w.logger.Error("get network for ownership check", "error", err)
			http.Error(rw, "Failed to load network", http.StatusInternalServerError)
			return
		}
		if network.CAID == "" {
			http.Error(rw, "Unauthorized", http.StatusForbidden)
			return
		}
		ca, err := w.store.GetCA(r.Context(), network.CAID)
		if err != nil || ca.OwnerOperatorID != op.ID {
			http.Error(rw, "Unauthorized", http.StatusForbidden)
			return
		}
	}

	form := newHostFormState(r)
	form.NetworkID = host.NetworkID // Force to current network

	// Load network for CIDR and error re-render
	network, err := w.store.GetNetwork(r.Context(), host.NetworkID)
	if err != nil {
		w.logger.Error("get network for update", "error", err)
		http.Error(rw, "Failed to load network", http.StatusInternalServerError)
		return
	}

	// Validation pipeline
	name := strings.TrimSpace(form.Name)
	if name == "" {
		w.renderHostEditError(rw, r, host, network, form, "name must not be empty")
		return
	}

	// Validate NebulaIPs
	if len(form.NebulaIPs) == 0 {
		w.renderHostEditError(rw, r, host, network, form, "at least one IP address is required")
		return
	}
	perRowErrors := make(map[int]string)
	for i, ip := range form.NebulaIPs {
		if err := validateHostIPForNetwork(r.Context(), w.store, host.NetworkID, ip, host.ID); err != nil {
			perRowErrors[i] = err.Error()
		}
	}
	if len(perRowErrors) > 0 {
		form.NebulaIPErrors = perRowErrors
		w.renderHostEditError(rw, r, host, network, form, "one or more IP addresses are invalid")
		return
	}

	if strings.TrimSpace(form.PublicIP) != "" {
		if _, err := netip.ParseAddr(form.PublicIP); err != nil {
			w.renderHostEditError(rw, r, host, network, form, models.FriendlyAddrError("public_ip", form.PublicIP))
			return
		}
	}

	var listenPort int
	if form.ListenPort != "" {
		var err error
		listenPort, err = strconv.Atoi(form.ListenPort)
		if err != nil {
			w.renderHostEditError(rw, r, host, network, form, "invalid listen_port: must be a number")
			return
		}
		if listenPort < 0 || listenPort > 65535 {
			w.renderHostEditError(rw, r, host, network, form, "listen_port must be between 0 and 65535")
			return
		}
	}

	role := models.HostRole(form.Role)
	if !models.ValidRole(role) {
		w.renderHostEditError(rw, r, host, network, form, "invalid role")
		return
	}
	if role == "" {
		role = models.HostRoleHost
	}

	if err := models.ValidateRoleReachability(role, form.PublicIP, listenPort); err != nil {
		w.renderHostEditError(rw, r, host, network, form, err.Error())
		return
	}

	var groups []string
	if g := strings.TrimSpace(form.Groups); g != "" {
		for _, s := range strings.Split(g, ",") {
			groups = append(groups, strings.TrimSpace(s))
		}
	}
	if groups == nil {
		groups = []string{}
	}

	advanced, err := parseAdvancedFromForm(r)
	if err != nil {
		w.renderHostEditError(rw, r, host, network, form, err.Error())
		return
	}
	if err := models.ValidateHostAdvanced(advanced); err != nil {
		w.renderHostEditError(rw, r, host, network, form, err.Error())
		return
	}

	// Snapshot for diff computation
	before := *host
	if host.Advanced != nil {
		beforeAdv := *host.Advanced
		before.Advanced = &beforeAdv
	}

	// Merge form into host
	host.Name = name
	host.NebulaIPs = form.NebulaIPs
	host.Groups = groups
	host.Role = role
	host.IsLighthouse = role == models.HostRoleLighthouse
	host.IsRelay = role == models.HostRoleRelay
	host.PublicIP = form.PublicIP
	host.ListenPort = listenPort
	host.Advanced = advanced

	// Compute diff
	jsonDiff, hasChanges, err := models.HostDiff(&before, host)
	if err != nil {
		w.logger.Error("compute host diff", "error", err)
		http.Error(rw, "Failed to compute changes", http.StatusInternalServerError)
		return
	}

	// Idempotent: no changes means success redirect (no audit entry)
	if !hasChanges {
		http.Redirect(rw, r, "/ui/hosts/"+host.ID, http.StatusSeeOther)
		return
	}

	// Update host; set PendingRekey if cert-bound fields (NebulaIPs, Name) changed
	host.UpdatedAt = time.Now()
	if !slicesEqual(before.NebulaIPs, host.NebulaIPs) || before.Name != host.Name {
		host.PendingRekey = true
	}
	if err := w.store.UpdateHost(r.Context(), host); err != nil {
		w.logger.Error("update host", "error", err)
		http.Error(rw, "Failed to update host", http.StatusInternalServerError)
		return
	}

	// Audit entry
	if err := w.store.AddAuditEntry(r.Context(), op.Username, "host.update", host.ID, string(jsonDiff)); err != nil {
		w.logger.Error("add audit entry", "error", err)
	}

	// Config version: update_host_config_version triggers config re-publish
	if err := w.store.UpdateHostConfigVersion(r.Context(), host.ID, 0); err != nil {
		w.logger.Error("update host config version", "error", err)
	}

	// Role change bumps network config version for topology propagation
	if before.Role != host.Role {
		if err := w.store.BumpNetworkConfigVersion(r.Context(), host.NetworkID); err != nil {
			w.logger.Error("bump network config version", "error", err)
		}
	}

	http.Redirect(rw, r, "/ui/hosts/"+host.ID, http.StatusSeeOther)
}

func (w *Web) handleHostBlock(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_, err := w.store.BlockHostAndAddToBlocklist(r.Context(), id, "blocked via UI")
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		w.logger.Error("block host", "error", err)
		http.Error(rw, "Failed to block host", http.StatusInternalServerError)
		return
	}

	rw.Header().Set("HX-Redirect", "/ui/hosts")
	rw.WriteHeader(http.StatusOK)
}

func (w *Web) handleHostDelete(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := w.store.DeleteHostAndBlockCert(r.Context(), id, "deleted via UI"); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(rw, r)
			return
		}
		w.logger.Error("delete host", "error", err)
		http.Error(rw, "Failed to delete host", http.StatusInternalServerError)
		return
	}

	rw.Header().Set("HX-Redirect", "/ui/hosts")
	rw.WriteHeader(http.StatusOK)
}

// networkCAID extracts CAID from a (possibly nil) network. Nil network
// happens when the operator submits an empty network_id; the host create
// path falls through to its own validation in that case.
func networkCAID(n *models.Network) string {
	if n == nil {
		return ""
	}
	return n.CAID
}

// --- Networks ---

func (w *Web) handleNetworks(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	cas, err := w.accessibleActiveCAs(r.Context(), op)
	if err != nil {
		w.logger.Error("list cas for networks page", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	w.renderForRequest(rw, r, "networks.html", map[string]any{
		"Active":     "networks",
		"Networks":   networks,
		"CAs":        cas,
		"HasCAs":     len(cas) > 0,
		"IsAdmin":    op.Role == "admin",
		"Form":       networkFormState{},
		"Error":      "",
		"ShowCreate": false,
	})
}

func (w *Web) handleNetworkCreate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}

	form := newNetworkFormState(r)

	cas, err := w.accessibleActiveCAs(r.Context(), op)
	if err != nil {
		w.logger.Error("list cas for network create", "error", err)
		http.Error(rw, "Failed to load CAs", http.StatusInternalServerError)
		return
	}
	// Non-admins must own at least one active CA. admins fall through
	// to the legacy "no CA tied to network" path so existing deployments
	// keep working until they migrate.
	if op.Role != "admin" && len(cas) == 0 {
		w.renderNetworksError(rw, r, form, cas, "You must create a CA before adding a network. Open the CAs page to mint one.")
		return
	}

	if form.Name == "" || len(form.CIDRs) == 0 {
		w.renderNetworksError(rw, r, form, cas, "name and at least one CIDR are required")
		return
	}
	// Validate each CIDR
	perRowErrors := make(map[int]string)
	for i, cidr := range form.CIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			perRowErrors[i] = models.FriendlyPrefixError("cidrs", cidr)
		}
	}
	if len(perRowErrors) > 0 {
		form.CIDRErrors = perRowErrors
		w.renderNetworksError(rw, r, form, cas, "one or more CIDRs are invalid")
		return
	}

	caID := form.CAID
	if caID == "" && op.Role != "admin" {
		if len(cas) == 1 {
			caID = cas[0].ID
		} else {
			w.renderNetworksError(rw, r, form, cas, "pick a CA to sign certificates for this network")
			return
		}
	}
	if caID != "" && !containsCAID(cas, caID) {
		w.renderNetworksError(rw, r, form, cas, "selected CA is not accessible to you")
		return
	}

	network := &models.Network{
		ID:        uuid.New().String(),
		Name:      form.Name,
		CIDRs:     form.CIDRs,
		CAID:      caID,
		CreatedAt: time.Now(),
	}

	if err := w.store.CreateNetwork(r.Context(), network); err != nil {
		w.logger.Error("create network", "error", err)
		http.Error(rw, "Failed to create network", http.StatusInternalServerError)
		return
	}

	http.Redirect(rw, r, "/ui/networks", http.StatusSeeOther)
}

func (w *Web) handleGenerateMobileBundle(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := w.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		w.logger.Error("get host for mobile bundle", "error", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Verify host is mobile
	if host.Kind != models.HostKindMobile {
		http.Error(rw, "Host is not a mobile host", http.StatusBadRequest)
		return
	}

	// Operator ownership check: non-admin operators must own the CA
	op := w.session.CurrentOperator(r)
	if op != nil && op.Role != "admin" {
		network, err := w.store.GetNetwork(r.Context(), host.NetworkID)
		if err != nil {
			w.logger.Error("get network for ownership check", "error", err)
			http.Error(rw, "Failed to load network", http.StatusInternalServerError)
			return
		}
		if network.CAID == "" {
			http.Error(rw, "Unauthorized", http.StatusForbidden)
			return
		}
		ca, err := w.store.GetCA(r.Context(), network.CAID)
		if err != nil || ca.OwnerOperatorID != op.ID {
			http.Error(rw, "Unauthorized", http.StatusForbidden)
			return
		}
	}

	w.renderMobileBundle(rw, r, host)
}

// renderMobileBundle builds a fresh certificate + YAML bundle for the given
// mobile host and renders host_mobile_bundle.html with the QR code. The private
// key inside the bundle is shown only once, so the response is marked no-store.
// Called from handleGenerateMobileBundle (explicit regenerate button) and from
// handleHostCreate (initial creation of a mobile host).
func (w *Web) renderMobileBundle(rw http.ResponseWriter, r *http.Request, host *models.Host) {
	bundle, err := mobilebundle.Build(r.Context(), w.store, w.caResolver, host)
	if err != nil {
		w.logger.Error("build mobile bundle", "error", err)
		http.Error(rw, fmt.Sprintf("Failed to generate bundle: %v", err), http.StatusInternalServerError)
		return
	}
	qrSVG, qrErr := renderQRSVG(string(bundle))
	downloadHref := "data:application/yaml;base64," + base64.StdEncoding.EncodeToString(bundle)
	rw.Header().Set("Cache-Control", "no-store")
	w.renderForRequest(rw, r, "host_mobile_bundle.html", map[string]any{
		"Host":         host,
		"YAML":         string(bundle),
		"QRSVG":        template.HTML(qrSVG),
		"QRError":      qrErr,
		"DownloadHref": template.URL(downloadHref),
		"Active":       "hosts",
	})
}

// slicesEqual reports whether two string slices are equal (same length and same elements in same order).
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
