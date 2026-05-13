package web

import (
	"context"
	"net/http"

	"github.com/juev/nebula-mesh/internal/models"
)

// hostFormState captures the values submitted to /ui/hosts so a validation
// failure can re-render host_new.html with the operator's inputs preserved
// instead of dropping them on a bare 400 error page (issue #91).
//
// String types throughout — including ListenPort and AdvMTU — so that the
// template can echo the operator's literal input back verbatim ("70000")
// even when it failed numeric validation.
type hostFormState struct {
	NetworkID       string
	Name            string
	NebulaIP        string
	Role            string
	Groups          string
	PublicIP        string
	ListenPort      string
	AdvListenHost   string
	AdvMTU          string
	AdvTunDevice    string
	AdvPunchy       string
	AdvUnsafeRoutes string
}

func newHostFormState(r *http.Request) hostFormState {
	return hostFormState{
		NetworkID:       r.FormValue("network_id"),
		Name:            r.FormValue("name"),
		NebulaIP:        r.FormValue("nebula_ip"),
		Role:            r.FormValue("role"),
		Groups:          r.FormValue("groups"),
		PublicIP:        r.FormValue("public_ip"),
		ListenPort:      r.FormValue("listen_port"),
		AdvListenHost:   r.FormValue("adv_listen_host"),
		AdvMTU:          r.FormValue("adv_mtu"),
		AdvTunDevice:    r.FormValue("adv_tun_device"),
		AdvPunchy:       r.FormValue("adv_punchy"),
		AdvUnsafeRoutes: r.FormValue("adv_unsafe_routes"),
	}
}

// networkFormState is the network-create equivalent of hostFormState.
// CAID captures the operator's CA selection so the form can re-render
// without losing it (issue #93 enforces that every network is tied to a
// CA the operator owns).
type networkFormState struct {
	Name string
	CIDR string
	CAID string
}

func newNetworkFormState(r *http.Request) networkFormState {
	return networkFormState{
		Name: r.FormValue("name"),
		CIDR: r.FormValue("cidr"),
		CAID: r.FormValue("ca_id"),
	}
}

// accessibleActiveCAs returns the active CAs the operator is allowed to
// pick as the signing CA for a new network. admins see every active CA in
// the system; users see only their own (mirrors handleCAsList in cas.go,
// plus a Status=Active filter so retired CAs cannot ground a new network).
func (w *Web) accessibleActiveCAs(ctx context.Context, op *models.Operator) ([]*models.CA, error) {
	var (
		cas []*models.CA
		err error
	)
	if op.Role == "admin" {
		cas, err = w.store.ListCAs(ctx)
	} else {
		cas, err = w.store.ListCAsByOwner(ctx, op.ID)
	}
	if err != nil {
		return nil, err
	}
	out := make([]*models.CA, 0, len(cas))
	for _, c := range cas {
		if c.Status == models.CAStatusActive {
			out = append(out, c)
		}
	}
	return out, nil
}

// accessibleNetworks returns the networks an operator can attach a host
// to. admins see every network; users see only networks whose CAID
// points at a CA they own. Legacy networks with an empty CAID are
// visible to admins (they predate per-operator CAs) and hidden from
// users (issue #93 — a self-registered user must not silently inherit
// the seed admin's CA).
func (w *Web) accessibleNetworks(ctx context.Context, op *models.Operator) ([]*models.Network, error) {
	networks, err := w.store.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	if op.Role == "admin" {
		return networks, nil
	}
	cas, err := w.store.ListCAsByOwner(ctx, op.ID)
	if err != nil {
		return nil, err
	}
	owned := make(map[string]struct{}, len(cas))
	for _, c := range cas {
		owned[c.ID] = struct{}{}
	}
	out := make([]*models.Network, 0, len(networks))
	for _, n := range networks {
		if n.CAID == "" {
			continue
		}
		if _, ok := owned[n.CAID]; ok {
			out = append(out, n)
		}
	}
	return out, nil
}

// containsCAID reports whether the slice of CAs contains one with the
// given id. Linear scan — caller pages are always small (admins rarely
// have more than a handful of CAs, users have one or two).
func containsCAID(cas []*models.CA, id string) bool {
	for _, c := range cas {
		if c.ID == id {
			return true
		}
	}
	return false
}

// renderHostNewError re-renders /ui/hosts/new with the submitted form
// values preserved and an inline error banner. Returns 400 because the
// request payload is the cause; the body is a full HTML page so the
// browser does not show a bare error. Networks are filtered through
// accessibleNetworks so the operator only sees networks they own
// (issue #93).
func (w *Web) renderHostNewError(rw http.ResponseWriter, r *http.Request, form hostFormState, errMsg string) {
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
	w.renderForRequestWithStatus(rw, r, http.StatusBadRequest, "host_new.html", map[string]any{
		"Active":      "hosts",
		"Networks":    networks,
		"HasNetworks": len(networks) > 0,
		"Form":        form,
		"Error":       errMsg,
	})
}

// renderNetworksError re-renders /ui/networks with the create form
// expanded, the submitted values preserved, and an inline error banner.
// cas is the list of CAs the operator may pick from (issue #93). When
// empty the template hides the create form and shows the "create a CA
// first" alert instead.
func (w *Web) renderNetworksError(rw http.ResponseWriter, r *http.Request, form networkFormState, cas []*models.CA, errMsg string) {
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	op := w.session.CurrentOperator(r)
	isAdmin := op != nil && op.Role == "admin"
	w.renderForRequestWithStatus(rw, r, http.StatusBadRequest, "networks.html", map[string]any{
		"Active":     "networks",
		"Networks":   networks,
		"CAs":        cas,
		"HasCAs":     len(cas) > 0,
		"IsAdmin":    isAdmin,
		"Form":       form,
		"Error":      errMsg,
		"ShowCreate": true,
	})
}
