package web

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// requireAuth middleware redirects to login if not authenticated.
func (w *Web) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !w.session.IsAuthenticated(r) {
			http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

func (w *Web) handleLoginPage(rw http.ResponseWriter, _ *http.Request) {
	w.render(rw, "login.html", map[string]any{"Error": ""})
}

func (w *Web) handleLogin(rw http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	if username == "" {
		username = "admin"
	}
	password := r.FormValue("password")
	result, ok, err := w.session.Login(rw, r, username, password)
	if err != nil {
		w.logger.Error("login", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		w.render(rw, "login.html", map[string]any{"Error": "Invalid username or password"})
		return
	}
	if result.NeedsTOTP {
		http.Redirect(rw, r, "/ui/login/totp", http.StatusSeeOther)
		return
	}
	http.Redirect(rw, r, "/ui/", http.StatusSeeOther)
}

func (w *Web) handleTOTPLoginPage(rw http.ResponseWriter, r *http.Request) {
	if op := w.session.PendingOperator(r); op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	w.render(rw, "login_totp.html", map[string]any{"Error": ""})
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
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.failed", op.ID, "")
		w.render(rw, "login_totp.html", map[string]any{"Error": "Invalid TOTP code"})
		return
	}
	if err := w.session.CompleteTwoFactor(rw, r, op.ID); err != nil {
		w.logger.Error("complete 2fa", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	details := "totp"
	if usedRecovery {
		details = "recovery"
	}
	_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.verified", op.ID, details)
	http.Redirect(rw, r, "/ui/", http.StatusSeeOther)
}

func (w *Web) handleLogout(rw http.ResponseWriter, r *http.Request) {
	w.session.Logout(rw, r)
	http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
}

// --- 2FA management ---

func (w *Web) handleTwoFAPage(rw http.ResponseWriter, r *http.Request) {
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	w.render(rw, "twofa.html", map[string]any{
		"Active":      "2fa",
		"Operator":    op,
		"TOTPEnabled": op.TOTPEnabled,
		"Setup":       nil,
		"NewCodes":    nil,
		"Error":       "",
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
	w.render(rw, "twofa.html", map[string]any{
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
		w.render(rw, "twofa.html", map[string]any{
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
	w.render(rw, "twofa.html", map[string]any{
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
	password := r.FormValue("password")
	if err := bcrypt.CompareHashAndPassword([]byte(op.PasswordHash), []byte(password)); err != nil {
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "operator.2fa.disable_failed", op.ID, "")
		w.render(rw, "twofa.html", map[string]any{
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
	w.render(rw, "twofa.html", map[string]any{
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
// human-readable network name. Embedding keeps every existing template
// field access (.ID, .Name, .NebulaIP, …) working unchanged.
type hostView struct {
	*models.Host
	NetworkName string
}

// buildHostViews resolves NetworkID → Network.Name for each host. If the
// host's network is not present in networks, NetworkName is left empty so
// the template can fall back to displaying the UUID.
func buildHostViews(hosts []*models.Host, networks []*models.Network) []hostView {
	if len(hosts) == 0 {
		return nil
	}
	idx := make(map[string]string, len(networks))
	for _, n := range networks {
		idx[n.ID] = n.Name
	}
	out := make([]hostView, len(hosts))
	for i, h := range hosts {
		out[i] = hostView{Host: h, NetworkName: idx[h.NetworkID]}
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

	w.render(rw, "dashboard.html", map[string]any{
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
	w.render(rw, "dashboard.html", map[string]any{
		"Active": "dashboard",
		"Stats":  stats,
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

	w.render(rw, "hosts.html", map[string]any{
		"Active": "hosts",
		"Hosts":  buildHostViews(hosts, networks),
	})
}

func (w *Web) handleHostNew(rw http.ResponseWriter, r *http.Request) {
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks for host form", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	w.render(rw, "host_new.html", map[string]any{
		"Active":   "hosts",
		"Networks": networks,
	})
}

func (w *Web) handleHostCreate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}

	nebulaIP := r.FormValue("nebula_ip")
	if nebulaIP != "" {
		if _, err := netip.ParseAddr(nebulaIP); err != nil {
			http.Error(rw, "invalid nebula_ip: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	listenPortStr := r.FormValue("listen_port")
	var listenPort int
	if listenPortStr != "" {
		var err error
		listenPort, err = strconv.Atoi(listenPortStr)
		if err != nil {
			http.Error(rw, "invalid listen_port: must be a number", http.StatusBadRequest)
			return
		}
		if listenPort < 0 || listenPort > 65535 {
			http.Error(rw, "listen_port must be between 0 and 65535", http.StatusBadRequest)
			return
		}
	}
	role := models.HostRole(r.FormValue("role"))
	if !models.ValidRole(role) {
		http.Error(rw, "invalid role", http.StatusBadRequest)
		return
	}
	if role == "" {
		role = models.HostRoleHost
	}

	var groups []string
	if g := strings.TrimSpace(r.FormValue("groups")); g != "" {
		for _, s := range strings.Split(g, ",") {
			groups = append(groups, strings.TrimSpace(s))
		}
	}
	if groups == nil {
		groups = []string{}
	}

	now := time.Now()
	host := &models.Host{
		ID:           uuid.New().String(),
		NetworkID:    r.FormValue("network_id"),
		Name:         r.FormValue("name"),
		NebulaIP:     nebulaIP,
		Groups:       groups,
		Role:         role,
		IsLighthouse: role == models.HostRoleLighthouse,
		IsRelay:      role == models.HostRoleRelay,
		PublicIP:     r.FormValue("public_ip"),
		ListenPort:   listenPort,
		Status:       models.HostStatusPending,
		CreatedAt:    now,
		UpdatedAt:    now,
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

	w.render(rw, "host_detail.html", map[string]any{
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

	w.render(rw, "host_detail.html", map[string]any{
		"Active": "hosts",
		"Host":   host,
	})
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

// --- Networks ---

func (w *Web) handleNetworks(rw http.ResponseWriter, r *http.Request) {
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	w.render(rw, "networks.html", map[string]any{
		"Active":   "networks",
		"Networks": networks,
	})
}

func (w *Web) handleNetworkCreate(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	cidr := r.FormValue("cidr")
	if name == "" || cidr == "" {
		http.Error(rw, "name and cidr are required", http.StatusBadRequest)
		return
	}
	if _, err := netip.ParsePrefix(cidr); err != nil {
		http.Error(rw, "invalid CIDR: "+err.Error(), http.StatusBadRequest)
		return
	}

	network := &models.Network{
		ID:        uuid.New().String(),
		Name:      name,
		CIDR:      cidr,
		CreatedAt: time.Now(),
	}

	if err := w.store.CreateNetwork(r.Context(), network); err != nil {
		w.logger.Error("create network", "error", err)
		http.Error(rw, "Failed to create network", http.StatusInternalServerError)
		return
	}

	http.Redirect(rw, r, "/ui/networks", http.StatusSeeOther)
}
