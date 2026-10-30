package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/forgekeep/nebula-mesh/internal/hostdns"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// networkDNSForm holds the raw host DNS fields, so a rejected form comes back
// as the operator typed it.
type networkDNSForm struct {
	Nameservers   string
	MatchDomains  string
	SearchDomains string
	Error         string
}

func newNetworkDNSForm(r *http.Request) networkDNSForm {
	return networkDNSForm{
		Nameservers:   r.FormValue("host_dns_nameservers"),
		MatchDomains:  r.FormValue("host_dns_match_domains"),
		SearchDomains: r.FormValue("host_dns_search_domains"),
	}
}

func (f networkDNSForm) settings() (hostdns.Settings, error) {
	return hostdns.Settings{
		Nameservers:   splitCommaList(f.Nameservers),
		MatchDomains:  splitCommaList(f.MatchDomains),
		SearchDomains: splitCommaList(f.SearchDomains),
	}.Normalize()
}

// networkView is one row of the networks page.
type networkView struct {
	*models.Network
	HostDNS hostdns.Settings
	DNSForm networkDNSForm
	DNSOpen bool
}

func (w *Web) buildNetworkViews(ctx context.Context, networks []*models.Network) []networkView {
	views := make([]networkView, 0, len(networks))
	for _, n := range networks {
		settings := w.loadNetworkHostDNS(ctx, n.ID)
		views = append(views, networkView{Network: n, HostDNS: settings, DNSForm: networkDNSForm{
			Nameservers:   strings.Join(settings.Nameservers, "\n"),
			MatchDomains:  strings.Join(settings.MatchDomains, "\n"),
			SearchDomains: strings.Join(settings.SearchDomains, "\n"),
		}})
	}
	return views
}

// loadNetworkHostDNS returns the stored setting, or the off state when there
// is none or it cannot be read; the page must still list the network.
func (w *Web) loadNetworkHostDNS(ctx context.Context, networkID string) hostdns.Settings {
	raw, err := w.store.GetNetworkConfig(ctx, networkID, hostdns.StoreKey)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			w.logger.Error("get host dns for networks page", "network", networkID, "error", err)
		}
		return hostdns.Default()
	}
	settings, err := hostdns.Decode(raw)
	if err != nil {
		w.logger.Error("decode host dns for networks page", "network", networkID, "error", err)
		return hostdns.Default()
	}
	return settings
}

// saveNetworkHostDNS stores the setting and moves the network config version:
// agents render the stanza, so every host must receive its config again.
func (w *Web) saveNetworkHostDNS(ctx context.Context, actor, networkID string, settings hostdns.Settings) error {
	raw, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	if err := w.store.SetNetworkConfigAndBumpVersion(ctx, networkID, hostdns.StoreKey, string(raw)); err != nil {
		return err
	}
	_ = w.store.AddAuditEntry(ctx, actor, "network.host_dns.update", networkID, string(raw))
	return nil
}

// loadAccessibleNetwork loads the network named by the {id} URL param and
// enforces that the session operator may change it: admins may act on any
// network, a non-admin must own its CA (SEC-TENANT-001). On failure it writes
// the response and returns ok=false.
func (w *Web) loadAccessibleNetwork(rw http.ResponseWriter, r *http.Request, op *models.Operator) (*models.Network, bool) {
	network, err := w.store.GetNetwork(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, r)
		return nil, false
	}
	if err != nil {
		w.logger.Error("get network", "error", err)
		http.Error(rw, "Failed to load network", http.StatusInternalServerError)
		return nil, false
	}
	if op.Role == "admin" {
		return network, true
	}
	if network.CAID != "" {
		ca, err := w.store.GetCA(r.Context(), network.CAID)
		if err == nil && ca.OwnerOperatorID == op.ID {
			return network, true
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			w.logger.Error("get network ca", "error", err)
			http.Error(rw, "Failed to load network", http.StatusInternalServerError)
			return nil, false
		}
	}
	http.Error(rw, "forbidden", http.StatusForbidden)
	return nil, false
}

func (w *Web) handleNetworkHostDNS(rw http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(rw, "bad request", http.StatusBadRequest)
		return
	}
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	network, ok := w.loadAccessibleNetwork(rw, r, op)
	if !ok {
		return
	}
	form := newNetworkDNSForm(r)
	settings, err := form.settings()
	if err != nil {
		form.Error = err.Error()
		w.renderNetworkDNSError(rw, r, op, network.ID, form)
		return
	}
	current := w.loadNetworkHostDNS(r.Context(), network.ID)
	if !slices.Equal(current.Nameservers, settings.Nameservers) ||
		!slices.Equal(current.MatchDomains, settings.MatchDomains) ||
		!slices.Equal(current.SearchDomains, settings.SearchDomains) {
		if err := w.saveNetworkHostDNS(r.Context(), op.Username, network.ID, settings); err != nil {
			if errors.Is(err, store.ErrMeshImportInProgress) {
				http.Error(rw, "Mesh import collection is in progress for this network", http.StatusConflict)
				return
			}
			w.logger.Error("save host dns", "network", network.ID, "error", err)
			http.Error(rw, "Failed to save host DNS", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(rw, r, "/ui/networks", http.StatusSeeOther)
}

// renderNetworkDNSError re-renders the networks page with the rejected form
// open on its own row.
func (w *Web) renderNetworkDNSError(rw http.ResponseWriter, r *http.Request, op *models.Operator, networkID string, form networkDNSForm) {
	networks, err := w.accessibleNetworks(r.Context(), op)
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
	views := w.buildNetworkViews(r.Context(), networks)
	for i := range views {
		if views[i].ID == networkID {
			views[i].DNSForm = form
			views[i].DNSOpen = true
		}
	}
	w.renderForRequestWithStatus(rw, r, http.StatusBadRequest, "networks.html", map[string]any{
		"Active":     "networks",
		"Networks":   views,
		"CAs":        cas,
		"HasCAs":     len(cas) > 0,
		"IsAdmin":    op.Role == "admin",
		"Form":       networkFormState{CIDRErrors: make(map[int]string)},
		"Error":      "",
		"ShowCreate": false,
	})
}
