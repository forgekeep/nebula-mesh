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

// Web is the web UI handler.
type Web struct {
	router    chi.Router
	store     store.Store
	templates map[string]*template.Template
	logger    *slog.Logger
	session   *SessionManager
}

// New creates a new Web UI handler.
func New(s store.Store, password string, logger *slog.Logger) (*Web, error) {
	w := &Web{
		store:     s,
		logger:    logger,
		session:   NewSessionManager(password),
		templates: make(map[string]*template.Template),
	}

	// Parse each page template with layout
	pages := []string{
		"dashboard.html",
		"hosts.html",
		"host_new.html",
		"host_detail.html",
		"networks.html",
	}
	for _, page := range pages {
		tmpl, err := template.ParseFS(templateFS, "templates/layout.html", "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		w.templates[page] = tmpl
	}

	// Login is standalone (no layout)
	loginTmpl, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}
	w.templates["login.html"] = loginTmpl

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

func (w *Web) render(rw http.ResponseWriter, name string, data any) {
	tmpl, ok := w.templates[name]
	if !ok {
		w.logger.Error("template not found", "template", name)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	// For pages with layout, execute "layout.html"; for standalone pages, execute the file directly
	execName := "layout.html"
	if name == "login.html" {
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
