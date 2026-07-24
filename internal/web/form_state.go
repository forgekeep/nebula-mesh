package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// trimEmpty returns a new slice with empty strings removed from src.
// Used to clean up form POST values for array fields (cidrs, nebula_ips).
func trimEmpty(src []string) []string {
	if len(src) == 0 {
		return []string{}
	}
	var out []string
	for _, s := range src {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// hostFormState captures the values submitted to /ui/hosts so a validation
// failure can re-render host_new.html with the operator's inputs preserved
// instead of dropping them on a bare 400 error page (issue #91).
//
// String types throughout — including ListenPort and AdvMTU — so that the
// template can echo the operator's literal input back verbatim ("70000")
// even when it failed numeric validation.
// NebulaIPs is a slice to support multiple overlay addresses per host (issue #108).
// NebulaIPErrors maps row index to per-row error messages for inline rendering.
type hostFormState struct {
	NetworkID          string
	Name               string
	NebulaIPs          []string
	NebulaIPErrors     map[int]string
	Role               string
	Groups             string
	PublicIP           string
	ListenPort         string
	AdvListenHost      string
	AdvMTU             string
	AdvTunDevice       string
	AdvPunchy          string
	AdvUnsafeRoutes    string
	AdvFirewallInbound string
	Kind               string
	Variant            string
}

func newHostFormState(r *http.Request) hostFormState {
	return hostFormState{
		NetworkID:          r.FormValue("network_id"),
		Name:               r.FormValue("name"),
		NebulaIPs:          trimEmpty(r.Form["nebula_ips"]),
		NebulaIPErrors:     make(map[int]string),
		Role:               r.FormValue("role"),
		Groups:             r.FormValue("groups"),
		PublicIP:           r.FormValue("public_ip"),
		ListenPort:         r.FormValue("listen_port"),
		AdvListenHost:      r.FormValue("adv_listen_host"),
		AdvMTU:             r.FormValue("adv_mtu"),
		AdvTunDevice:       r.FormValue("adv_tun_device"),
		AdvPunchy:          r.FormValue("adv_punchy"),
		AdvUnsafeRoutes:    r.FormValue("adv_unsafe_routes"),
		AdvFirewallInbound: r.FormValue("adv_firewall_inbound"),
		Kind:               r.FormValue("kind"),
		Variant:            r.FormValue("variant"),
	}
}

// networkFormState is the network-create equivalent of hostFormState.
// CAID captures the operator's CA selection so the form can re-render
// without losing it (issue #93 enforces that every network is tied to a
// CA the operator owns).
// CIDRs is a slice to support multiple CIDR blocks per network (issue #108).
// CIDRErrors maps row index to per-row error messages for inline rendering.
type networkFormState struct {
	Name       string
	CIDRs      []string
	CIDRErrors map[int]string
	CAID       string
}

func newNetworkFormState(r *http.Request) networkFormState {
	return networkFormState{
		Name:       r.FormValue("name"),
		CIDRs:      trimEmpty(r.Form["cidrs"]),
		CIDRErrors: make(map[int]string),
		CAID:       r.FormValue("ca_id"),
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
// (issue #93). If the form has a NetworkID, the selected network is
// also loaded to support parent CIDR dropdown for multi-address hosts.
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
	data := map[string]any{
		"Active":      "hosts",
		"Networks":    networks,
		"HasNetworks": len(networks) > 0,
		"Form":        form,
		"Error":       errMsg,
	}
	// Load the selected network if present, so template can show parent CIDR dropdowns
	if form.NetworkID != "" {
		if network, err := w.store.GetNetwork(r.Context(), form.NetworkID); err == nil {
			data["Network"] = network
		}
	}
	w.renderForRequestWithStatus(rw, r, http.StatusBadRequest, "host_new.html", data)
}

// renderNetworksError re-renders /ui/networks with the create form
// expanded, the submitted values preserved, and an inline error banner.
// cas is the list of CAs the operator may pick from (issue #93). When
// empty the template hides the create form and shows the "create a CA
// first" alert instead.
func (w *Web) renderNetworksError(rw http.ResponseWriter, r *http.Request, form networkFormState, cas []*models.CA, errMsg string) {
	op := w.session.CurrentOperator(r)
	// Scope the network list to what the operator may see — admins see all,
	// non-admins only networks under CAs they own. Without this the create-form
	// error re-render leaks every tenant's network names and CIDRs.
	var networks []*models.Network
	if op != nil {
		var err error
		networks, err = w.accessibleNetworks(r.Context(), op)
		if err != nil {
			w.logger.Error("list networks", "error", err)
			http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
			return
		}
	}
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

// hostFormStateFromHost serializes a Host record into hostFormState for
// re-rendering the edit form. String fields (ListenPort, AdvMTU) are
// converted to their string representations so the template can echo them
// verbatim without numeric formatting (issue #91).
func hostFormStateFromHost(h *models.Host) hostFormState {
	state := hostFormState{
		NetworkID:      h.NetworkID,
		Name:           h.Name,
		NebulaIPs:      h.NebulaIPs,
		NebulaIPErrors: make(map[int]string),
		Role:           string(h.Role),
		PublicIP:       h.PublicIP,
	}

	if h.ListenPort != 0 {
		state.ListenPort = strconv.Itoa(h.ListenPort)
	}

	if len(h.Groups) > 0 {
		state.Groups = strings.Join(h.Groups, ", ")
	}

	if h.Advanced != nil {
		state.AdvListenHost = h.Advanced.ListenHost
		if h.Advanced.MTU != 0 {
			state.AdvMTU = strconv.Itoa(h.Advanced.MTU)
		}
		state.AdvTunDevice = h.Advanced.TunDevice
		if h.Advanced.Punchy != nil {
			if *h.Advanced.Punchy {
				state.AdvPunchy = "true"
			} else {
				state.AdvPunchy = "false"
			}
		}

		// UnsafeRoutes: "CIDR via IP" per line
		for _, ur := range h.Advanced.UnsafeRoutes {
			if state.AdvUnsafeRoutes != "" {
				state.AdvUnsafeRoutes += "\n"
			}
			state.AdvUnsafeRoutes += ur.Route + " via " + ur.Via
		}

		// FirewallInbound: "PORT/PROTO from GROUP" per line
		for _, fr := range h.Advanced.FirewallInbound {
			if state.AdvFirewallInbound != "" {
				state.AdvFirewallInbound += "\n"
			}
			state.AdvFirewallInbound += fr.Port + "/" + fr.Proto + " from " + fr.Group
		}
	}

	return state
}

// renderHostEditError re-renders /ui/hosts/{id}/edit with the submitted form
// values preserved and an inline error banner. Returns 400 because the request
// payload is the cause. Mirrors renderHostNewError for consistency.
func (w *Web) renderHostEditError(rw http.ResponseWriter, r *http.Request, host *models.Host, network *models.Network, form hostFormState, errMsg string) {
	w.renderForRequestWithStatus(rw, r, http.StatusBadRequest, "host_edit.html", map[string]any{
		"Active":  "hosts",
		"Host":    host,
		"Network": network,
		"Form":    form,
		"Error":   errMsg,
	})
}

// operatorFormState captures form values for /ui/operators so a validation
// failure can re-render the form with Username/DisplayName/Role preserved.
// Password and PasswordConfirm are intentionally not stored to prevent
// secrets from being echoed in HTML re-renders.
// Errors maps field names to per-field error messages for inline rendering.
type operatorFormState struct {
	Username    string
	DisplayName string
	Role        string
	Errors      map[string]string
}

func newOperatorFormState(r *http.Request) operatorFormState {
	role := r.FormValue("role")
	if role == "" {
		role = "user"
	}
	return operatorFormState{
		Username:    strings.TrimSpace(r.FormValue("username")),
		DisplayName: strings.TrimSpace(r.FormValue("display_name")),
		Role:        role,
		Errors:      make(map[string]string),
	}
}

// renderOperatorNewError re-renders /ui/operators/new with the submitted form
// values preserved and per-field error messages. Returns 400 because the
// request payload is the cause. PasswordHint is a static string describing
// the active password policy.
func (w *Web) renderOperatorNewError(rw http.ResponseWriter, r *http.Request, form operatorFormState, hint string) {
	w.renderForRequestWithStatus(rw, r, http.StatusBadRequest, "operator_new.html", map[string]any{
		"Active":       "operators",
		"Form":         form,
		"PasswordHint": hint,
	})
}
