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
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/juev/nebula-mesh/internal/auth"
	"github.com/juev/nebula-mesh/internal/keystore"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/ratelimit"
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
	router                chi.Router
	store                 store.Store
	templates             map[string]*template.Template
	logger                *slog.Logger
	session               *SessionManager
	oidc                  *OIDC
	allowSelfRegistration bool
	loginRecorder         func(result, factor string)
	events                *EventBus
	limiter               *ratelimit.Limiter
	passwordPolicy        auth.Policy
	caMaster              *keystore.Master
	caResolver            *pki.CAResolver

	// apiKeyFlash holds freshly-minted operator API keys for one-shot
	// display on the next operator-detail render. Closes GHSA-9pg3-25fq-p6cc
	// by avoiding the raw token in the redirect URL. Keyed by the live
	// session-cookie value so a refresh on a different browser sees nothing.
	apiKeyFlashMu sync.Mutex
	apiKeyFlash   map[string]apiKeyFlashEntry
}

type apiKeyFlashEntry struct {
	Key     string
	KeyName string
	Expiry  time.Time
}

const apiKeyFlashTTL = 5 * time.Minute

// WithPasswordPolicy installs the password policy used by registration
// and any future self-service password change. Defaults to auth.Default()
// when never called.
func (w *Web) WithPasswordPolicy(p auth.Policy) { w.passwordPolicy = p }

// WithRateLimiter wires a shared rate limiter so auth + UI routes pick
// up the same per-IP buckets the API server uses. nil disables limiting.
func (w *Web) WithRateLimiter(l *ratelimit.Limiter) {
	w.limiter = l
	w.setupRoutes()
}

// WithCAResolver wires a CA resolver for mobile bundle generation.
func (w *Web) WithCAResolver(r *pki.CAResolver) {
	w.caResolver = r
}

// noStore tells the browser not to cache UI responses. Without this Chrome
// will sometimes serve a stale page from bfcache after a 303 redirect lands
// back on the same URL, so freshly created networks / hosts only appear
// after a hard reload.
func (w *Web) noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(rw, r)
	})
}

// rateLimitMiddleware blocks requests for ip+group when the bucket is
// drained. Audit log calls are made by the handler when the request is
// admitted; rate-limited refusals only emit the 429 + Retry-After here.
func (w *Web) rateLimitMiddleware(group string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if w.limiter == nil {
				next.ServeHTTP(rw, r)
				return
			}
			ip := w.limiter.ClientIP(r)
			ok, retry := w.limiter.Allow(ip, group)
			if !ok {
				masked := ratelimit.MaskIP(ip)
				_ = w.store.AddAuditEntry(r.Context(), "anonymous", "auth.rate_limited", masked, "route="+group)
				ratelimit.WriteRetryAfter(rw, retry)
				return
			}
			next.ServeHTTP(rw, r)
		})
	}
}

// WithLoginRecorder wires an external sink (typically the API server's
// Prometheus metrics) that observes the outcome of every UI login attempt.
// Must be set before ServeHTTP is invoked. Passing nil disables recording.
func (w *Web) WithLoginRecorder(f func(result, factor string)) {
	w.loginRecorder = f
}

// recordLogin is a nil-safe convenience wrapper used by the login handlers.
func (w *Web) recordLogin(result, factor string) {
	if w.loginRecorder != nil {
		w.loginRecorder(result, factor)
	}
}

// AllowSelfRegistration enables the public /ui/register flow. Must be set
// before ServeHTTP is invoked. Default is false.
func (w *Web) AllowSelfRegistration(allow bool) { w.allowSelfRegistration = allow }

// WithCookieSecure threads the resolved cookie-secure flag through to the
// session manager and (if attached) OIDC. Call after WithOIDC so the OIDC
// state cookie picks up the same flag. Closes GHSA-rqfj-vv8r-xhqc.
func (w *Web) WithCookieSecure(secure bool) {
	w.session.SetCookieSecure(secure)
	w.oidc.SetCookieSecure(secure) // nil-safe inside SetCookieSecure
}

// WithOIDC attaches an OIDC provider and registers its login/callback routes.
// Must be called before ServeHTTP is invoked.
func (w *Web) WithOIDC(o *OIDC) {
	w.oidc = o
	if o == nil {
		return
	}
	// Wire the auto-provision callback so OIDC can create default CA
	// for new user-role operators on their first login.
	o.provisionCA = w.provisionDefaultCA
	w.router.Get("/ui/oidc/login", o.HandleLogin)
	w.router.With(w.rateLimitMiddleware("auth")).Get("/ui/oidc/callback", o.HandleCallback)
}

// New creates a new Web UI handler.
func New(s store.Store, logger *slog.Logger) (*Web, error) {
	w := &Web{
		store:          s,
		logger:         logger,
		session:        NewSessionManager(s),
		templates:      make(map[string]*template.Template),
		passwordPolicy: auth.Default(),
	}

	// Parse each page template with layout
	pages := []string{
		"dashboard.html",
		"hosts.html",
		"host_new.html",
		"host_edit.html",
		"host_detail.html",
		"host_mobile_bundle.html",
		"networks.html",
		"twofa.html",
		"profile.html",
		"settings.html",
		"operators_list.html",
		"operator_new.html",
		"operator_detail.html",
		"cas_list.html",
		"ca_new.html",
		"ca_detail.html",
	}
	funcMap := template.FuncMap{
		"deref": func(p *bool) bool {
			if p == nil {
				return false
			}
			return *p
		},
	}

	for _, page := range pages {
		files := []string{"templates/layout.html", "templates/" + page}
		// dashboard.html references the "stats" partial via {{template "stats" .}}
		if page == "dashboard.html" {
			files = append(files, "templates/stats_partial.html")
		}
		tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, files...)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", page, err)
		}
		w.templates[page] = tmpl
	}

	// Login pages are standalone (no layout)
	for _, page := range []string{"login.html", "login_totp.html", "register.html"} {
		tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", page, err)
		}
		w.templates[page] = tmpl
	}

	// Standalone partial for HTMX polling — rendered without layout so the
	// `every 30s` swap on .stats-grid does not embed a whole new sidebar +
	// dashboard inside the existing one.
	partial, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/stats_partial.html")
	if err != nil {
		return nil, fmt.Errorf("parse stats_partial.html: %w", err)
	}
	w.templates["stats_partial.html"] = partial

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

	// Bare root redirects to the dashboard so first-time visitors land on /ui/
	// instead of a 404. Per issue #69, the catch-all mux now sends "/" to the
	// Web UI; this redirect keeps existing /ui/ links and bookmarks canonical
	// instead of switching every UI URL to bare root in one go.
	r.Get("/", func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, "/ui/", http.StatusFound)
	})

	// Login (public). Auth-group rate limit only on the form submissions
	// — GET pages render the form and a 429 there would just confuse
	// legitimate users who haven't yet pressed Submit.
	r.Get("/ui/login", w.handleLoginPage)
	r.With(w.rateLimitMiddleware("auth")).Post("/ui/login", w.handleLogin)
	r.Get("/ui/login/totp", w.handleTOTPLoginPage)
	r.With(w.rateLimitMiddleware("auth")).Post("/ui/login/totp", w.handleTOTPLogin)
	r.Get("/ui/register", w.handleRegisterPage)
	r.With(w.rateLimitMiddleware("auth")).Post("/ui/register", w.handleRegister)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(w.rateLimitMiddleware("ui"))
		r.Use(w.requireAuth)
		r.Use(w.noStore)
		r.Get("/ui/", w.handleDashboard)
		r.Get("/ui/hosts", w.handleHosts)
		r.Get("/ui/hosts/new", w.handleHostNew)
		r.Post("/ui/hosts", w.handleHostCreate)
		r.Get("/ui/hosts/{id}", w.handleHostDetail)
		r.Get("/ui/hosts/{id}/edit", w.handleHostEdit)
		r.Post("/ui/hosts/{id}/edit", w.handleHostUpdate)
		r.Post("/ui/hosts/{id}/mobile-bundle/generate", w.handleGenerateMobileBundle)
		r.Post("/ui/hosts/{id}/block", w.handleHostBlock)
		r.Delete("/ui/hosts/{id}", w.handleHostDelete)
		r.Get("/ui/networks", w.handleNetworks)
		r.Post("/ui/networks", w.handleNetworkCreate)
		r.Get("/ui/profile", w.handleProfilePage)
		r.Get("/ui/2fa", w.handleTwoFAPage)
		r.Get("/ui/2fa/required", w.handleTwoFARequired)
		r.Get("/ui/settings", w.handleSettingsPage)
		r.Post("/ui/settings", w.handleSettingsSave)

		// Admin-only operator + API-key management (issue #45).
		r.Group(func(r chi.Router) {
			r.Use(w.requireAdmin)
			r.Get("/ui/operators", w.handleOperatorsList)
			r.Get("/ui/operators/new", w.handleOperatorNewPage)
			r.Post("/ui/operators", w.handleOperatorCreate)
			r.Get("/ui/operators/{id}", w.handleOperatorDetail)
			r.Post("/ui/operators/{id}/disable", w.handleOperatorDisable)
			r.Post("/ui/operators/{id}/enable", w.handleOperatorEnable)
			r.Post("/ui/operators/{id}/reset-password", w.handleOperatorResetPassword)
			r.Post("/ui/operators/{id}/api-keys", w.handleOperatorCreateAPIKey)
			r.Post("/ui/operators/{id}/api-keys/{kid}/revoke", w.handleOperatorRevokeAPIKey)
		})

		// Per-operator CA management (issue #46). Available to every
		// authenticated operator; non-admins only see / act on the CAs
		// they own — enforced server-side by loadAccessibleCA.
		r.Get("/ui/cas", w.handleCAsList)
		r.Get("/ui/cas/new", w.handleCANewPage)
		r.Post("/ui/cas", w.handleCACreate)
		r.Get("/ui/cas/{id}", w.handleCADetail)
		r.Post("/ui/cas/{id}/retire", w.handleCARetire)
		r.Post("/ui/cas/{id}/rotate", w.handleCARotate)
		r.Post("/ui/cas/{id}/delete", w.handleCADelete)
		r.Post("/ui/2fa/setup", w.handleTwoFASetup)
		r.Post("/ui/2fa/enable", w.handleTwoFAEnable)
		r.Post("/ui/2fa/disable", w.handleTwoFADisable)
		r.Post("/ui/2fa/recovery-codes", w.handleTwoFARegenCodes)
		r.Get("/ui/partials/stats", w.handlePartialStats)
		r.Get("/ui/events", w.handleHostEvents)
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
	w.renderForRequestWithStatus(rw, r, 0, name, data)
}

// renderForRequestWithStatus is renderForRequest with an explicit HTTP
// status code (e.g. 400 for form validation errors). status=0 means "leave
// it to net/http" (defaults to 200).
func (w *Web) renderForRequestWithStatus(rw http.ResponseWriter, r *http.Request, status int, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	if _, present := data["CurrentUser"]; !present {
		data["CurrentUser"] = w.session.CurrentOperator(r)
	}
	w.renderWithStatus(rw, status, name, data)
}

func (w *Web) renderWithStatus(rw http.ResponseWriter, status int, name string, data map[string]any) {
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
	if name == "stats_partial.html" {
		execName = "stats"
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, execName, data); err != nil {
		w.logger.Error("render template", "template", name, "error", err)
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if status != 0 {
		rw.WriteHeader(status)
	}
	if _, err := buf.WriteTo(rw); err != nil {
		w.logger.Error("write response", "template", name, "error", err)
	}
}
