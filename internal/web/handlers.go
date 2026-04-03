package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/juev/nebula-mgmt/internal/models"
	"github.com/juev/nebula-mgmt/internal/store"
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
	ok, err := w.session.Login(rw, password)
	if err != nil {
		w.logger.Error("login", "error", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	if ok {
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

func (w *Web) getStats(ctx context.Context) (dashboardStats, error) {
	var stats dashboardStats

	networks, err := w.store.ListNetworks(ctx)
	if err != nil {
		return stats, fmt.Errorf("list networks: %w", err)
	}
	stats.Networks = len(networks)

	hosts, err := w.store.ListHosts(ctx, store.HostFilter{})
	if err != nil {
		return stats, fmt.Errorf("list hosts: %w", err)
	}
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
	return stats, nil
}

func (w *Web) handleDashboard(rw http.ResponseWriter, r *http.Request) {
	stats, err := w.getStats(r.Context())
	if err != nil {
		w.logger.Error("get stats", "error", err)
		http.Error(rw, "Failed to load dashboard", http.StatusInternalServerError)
		return
	}
	hosts, err := w.store.ListHosts(r.Context(), store.HostFilter{})
	if err != nil {
		w.logger.Error("list hosts for dashboard", "error", err)
		http.Error(rw, "Failed to load dashboard", http.StatusInternalServerError)
		return
	}

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
	stats, err := w.getStats(r.Context())
	if err != nil {
		w.logger.Error("get stats", "error", err)
		http.Error(rw, "Failed to load stats", http.StatusInternalServerError)
		return
	}
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
		http.Error(rw, "Failed to load hosts", http.StatusInternalServerError)
		return
	}

	w.render(rw, "hosts.html", map[string]any{
		"Active": "hosts",
		"Hosts":  hosts,
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
	}
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
		http.Error(rw, "Failed to create enrollment token", http.StatusInternalServerError)
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
	host, err := w.store.GetHost(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return
	}
	if err != nil {
		w.logger.Error("get host for block", "error", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if host.CertFingerprint != "" {
		if err := w.store.AddToBlocklist(r.Context(), host.CertFingerprint, host.ID, "blocked via UI"); err != nil {
			w.logger.Error("add to blocklist", "error", err)
			http.Error(rw, "Failed to block host", http.StatusInternalServerError)
			return
		}
	}
	if err := w.store.UpdateHostStatus(r.Context(), host.ID, models.HostStatusBlocked); err != nil {
		w.logger.Error("update host status", "error", err)
		http.Error(rw, "Failed to update host", http.StatusInternalServerError)
		return
	}

	rw.Header().Set("HX-Redirect", "/ui/hosts")
	rw.WriteHeader(http.StatusOK)
}

func (w *Web) handleHostDelete(rw http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	host, err := w.store.GetHost(r.Context(), id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		w.logger.Error("get host for delete", "error", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if host != nil && host.CertFingerprint != "" {
		if err := w.store.AddToBlocklist(r.Context(), host.CertFingerprint, host.ID, "deleted via UI"); err != nil {
			w.logger.Error("add to blocklist on delete", "error", err)
		}
	}
	if err := w.store.DeleteHost(r.Context(), id); err != nil {
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
