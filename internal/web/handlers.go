package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/store"
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
	password := r.FormValue("password")
	if w.session.Login(rw, password) {
		http.Redirect(rw, r, "/ui/", http.StatusSeeOther)
		return
	}
	w.render(rw, "login.html", map[string]any{"Error": "Invalid password"})
}

func (w *Web) handleLogout(rw http.ResponseWriter, r *http.Request) {
	w.session.Logout(rw, r)
	http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
}

// --- Dashboard ---

type dashboardStats struct {
	TotalHosts    int
	EnrolledHosts int
	PendingHosts  int
	BlockedHosts  int
	Networks      int
	ExpiringCerts int
}

func (w *Web) getStats(ctx context.Context) dashboardStats {
	var stats dashboardStats

	networks, _ := w.store.ListNetworks(ctx)
	stats.Networks = len(networks)

	hosts, _ := w.store.ListHosts(ctx, store.HostFilter{})
	stats.TotalHosts = len(hosts)
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
	stats := w.getStats(r.Context())
	hosts, _ := w.store.ListHosts(r.Context(), store.HostFilter{})

	// Take last 10
	if len(hosts) > 10 {
		hosts = hosts[len(hosts)-10:]
	}

	w.render(rw, "dashboard.html", map[string]any{
		"Active":      "dashboard",
		"Stats":       stats,
		"RecentHosts": hosts,
	})
}

func (w *Web) handlePartialStats(rw http.ResponseWriter, r *http.Request) {
	stats := w.getStats(r.Context())
	w.render(rw, "dashboard.html", map[string]any{
		"Active": "dashboard",
		"Stats":  stats,
	})
}

// --- Hosts ---

func (w *Web) handleHosts(rw http.ResponseWriter, r *http.Request) {
	hosts, err := w.store.ListHosts(r.Context(), store.HostFilter{})
	if err != nil {
		w.logger.Error("list hosts", "error", err)
	}

	w.render(rw, "hosts.html", map[string]any{
		"Active": "hosts",
		"Hosts":  hosts,
	})
}

func (w *Web) handleHostNew(rw http.ResponseWriter, r *http.Request) {
	networks, _ := w.store.ListNetworks(r.Context())
	w.render(rw, "host_new.html", map[string]any{
		"Active":   "hosts",
		"Networks": networks,
	})
}

func (w *Web) handleHostCreate(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	listenPort, _ := strconv.Atoi(r.FormValue("listen_port"))
	role := models.HostRole(r.FormValue("role"))
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
		NebulaIP:     r.FormValue("nebula_ip"),
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

	if err := w.store.CreateHost(r.Context(), host); err != nil {
		w.logger.Error("create host", "error", err)
		http.Error(rw, "Failed to create host", http.StatusInternalServerError)
		return
	}

	token := &models.EnrollmentToken{
		ID:        uuid.New().String(),
		HostID:    host.ID,
		Token:     uuid.New().String(),
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	if err := w.store.CreateToken(r.Context(), token); err != nil {
		w.logger.Error("create token", "error", err)
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
	if err == store.ErrNotFound {
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
	host, err := w.store.GetHost(r.Context(), id)
	if err != nil {
		http.NotFound(rw, r)
		return
	}

	if host.CertFingerprint != "" {
		w.store.AddToBlocklist(r.Context(), host.CertFingerprint, host.ID, "blocked via UI")
	}
	host.Status = models.HostStatusBlocked
	w.store.UpdateHost(r.Context(), host)

	// htmx: return updated row
	rw.Header().Set("HX-Redirect", "/ui/hosts")
	rw.WriteHeader(http.StatusOK)
}

func (w *Web) handleHostDelete(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, _ := w.store.GetHost(r.Context(), id)
	if host != nil && host.CertFingerprint != "" {
		w.store.AddToBlocklist(r.Context(), host.CertFingerprint, host.ID, "deleted via UI")
	}
	w.store.DeleteHost(r.Context(), id)

	rw.Header().Set("HX-Redirect", "/ui/hosts")
	rw.WriteHeader(http.StatusOK)
}

// --- Networks ---

func (w *Web) handleNetworks(rw http.ResponseWriter, r *http.Request) {
	networks, _ := w.store.ListNetworks(r.Context())
	w.render(rw, "networks.html", map[string]any{
		"Active":   "networks",
		"Networks": networks,
	})
}

func (w *Web) handleNetworkCreate(rw http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	network := &models.Network{
		ID:        uuid.New().String(),
		Name:      r.FormValue("name"),
		CIDR:      r.FormValue("cidr"),
		CreatedAt: time.Now(),
	}

	if err := w.store.CreateNetwork(r.Context(), network); err != nil {
		w.logger.Error("create network", "error", err)
		http.Error(rw, "Failed to create network", http.StatusInternalServerError)
		return
	}

	http.Redirect(rw, r, "/ui/networks", http.StatusSeeOther)
}
