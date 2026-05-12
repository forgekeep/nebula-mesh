package web

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juev/nebula-mesh/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Session exposes the underlying session manager so callers can wire up
// alternative login flows (e.g. OIDC) that need to issue sessions.
func (w *Web) Session() *SessionManager { return w.session }

// Web is the web UI handler.
type Web struct {
	router                 chi.Router
	store                  store.Store
	templates              map[string]*template.Template
	logger                 *slog.Logger
	session                *SessionManager
	oidc                   *OIDC
	allowSelfRegistration  bool
}

// AllowSelfRegistration enables the public /ui/register flow. Must be set
// before ServeHTTP is invoked. Default is false.
func (w *Web) AllowSelfRegistration(allow bool) { w.allowSelfRegistration = allow }

// WithOIDC attaches an OIDC provider and registers its login/callback routes.
// Must be called before ServeHTTP is invoked.
func (w *Web) WithOIDC(o *OIDC) {
	w.oidc = o
	if o == nil {
		return
	}
	w.router.Get("/ui/oidc/login", o.HandleLogin)
	w.router.Get("/ui/oidc/callback", o.HandleCallback)
}

// New creates a new Web UI handler.
func New(s store.Store, logger *slog.Logger) (*Web, error) {
	w := &Web{
		store:     s,
		logger:    logger,
		session:   NewSessionManager(s),
		templates: make(map[string]*template.Template),
	}

	// Parse each page template with layout
	pages := []string{
		"dashboard.html",
		"hosts.html",
		"host_new.html",
		"host_detail.html",
		"networks.html",
		"twofa.html",
		"profile.html",
	}
	for _, page := range pages {
		tmpl, err := template.ParseFS(templateFS, "templates/layout.html", "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		w.templates[page] = tmpl
	}

	// Login pages are standalone (no layout)
	for _, page := range []string{"login.html", "login_totp.html", "register.html"} {
		tmpl, err := template.ParseFS(templateFS, "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", page, err)
		}
		w.templates[page] = tmpl
	}

	w.setupRoutes()
	return w, nil
}

func (w *Web) setupRoutes() {
	r := chi.NewRouter()

	// Static files
	staticSub, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Favicon (public, served from embedded SVG)
	r.Get("/favicon.ico", w.handleFavicon)

	// Login (public)
	r.Get("/ui/login", w.handleLoginPage)
	r.Post("/ui/login", w.handleLogin)
	r.Get("/ui/login/totp", w.handleTOTPLoginPage)
	r.Post("/ui/login/totp", w.handleTOTPLogin)
	r.Get("/ui/register", w.handleRegisterPage)
	r.Post("/ui/register", w.handleRegister)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(w.requireAuth)
		r.Get("/ui/", w.handleDashboard)
		r.Get("/ui/hosts", w.handleHosts)
		r.Get("/ui/hosts/new", w.handleHostNew)
		r.Post("/ui/hosts", w.handleHostCreate)
		r.Get("/ui/hosts/{id}", w.handleHostDetail)
		r.Post("/ui/hosts/{id}/block", w.handleHostBlock)
		r.Delete("/ui/hosts/{id}", w.handleHostDelete)
		r.Get("/ui/networks", w.handleNetworks)
		r.Post("/ui/networks", w.handleNetworkCreate)
		r.Get("/ui/profile", w.handleProfilePage)
		r.Get("/ui/2fa", w.handleTwoFAPage)
		r.Post("/ui/2fa/setup", w.handleTwoFASetup)
		r.Post("/ui/2fa/enable", w.handleTwoFAEnable)
		r.Post("/ui/2fa/disable", w.handleTwoFADisable)
		r.Post("/ui/2fa/recovery-codes", w.handleTwoFARegenCodes)
		r.Get("/ui/partials/stats", w.handlePartialStats)
		r.Get("/ui/logout", w.handleLogout)
	})

	w.router = r
}

// StartSessionCleanup starts periodic removal of expired sessions.
// Stops when ctx is cancelled.
func (w *Web) StartSessionCleanup(ctx context.Context) {
	w.session.StartCleanup(ctx, 1*time.Hour)
}

// ServeHTTP implements http.Handler.
func (w *Web) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	w.router.ServeHTTP(rw, r)
}

// renderForRequest renders a template with the current operator (if any)
// injected as `.CurrentUser`, so the shared layout can show the profile chip
// without each handler having to pass it explicitly. Standalone login /
// register pages take this path too — the field is just unused there.
func (w *Web) renderForRequest(rw http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if _, present := data["CurrentUser"]; !present {
		data["CurrentUser"] = w.session.CurrentOperator(r)
	}
	w.render(rw, name, data)
}

func (w *Web) render(rw http.ResponseWriter, name string, data any) {
	tmpl, ok := w.templates[name]
	if !ok {
		w.logger.Error("template not found", "template", name)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// For pages with layout, execute "layout.html"; for standalone pages, execute the file directly
	execName := "layout.html"
	if name == "login.html" || name == "login_totp.html" || name == "register.html" {
		execName = name
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, execName, data); err != nil {
		w.logger.Error("render template", "template", name, "error", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := buf.WriteTo(rw); err != nil {
		w.logger.Error("write response", "template", name, "error", err)
	}
}
