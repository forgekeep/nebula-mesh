package web

import "net/http"

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
type networkFormState struct {
	Name string
	CIDR string
}

func newNetworkFormState(r *http.Request) networkFormState {
	return networkFormState{
		Name: r.FormValue("name"),
		CIDR: r.FormValue("cidr"),
	}
}

// renderHostNewError re-renders /ui/hosts/new with the submitted form
// values preserved and an inline error banner. Returns 400 because the
// request payload is the cause; the body is a full HTML page so the
// browser does not show a bare error.
func (w *Web) renderHostNewError(rw http.ResponseWriter, r *http.Request, form hostFormState, errMsg string) {
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks for host form", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	w.renderForRequestWithStatus(rw, r, http.StatusBadRequest, "host_new.html", map[string]any{
		"Active":   "hosts",
		"Networks": networks,
		"Form":     form,
		"Error":    errMsg,
	})
}

// renderNetworksError re-renders /ui/networks with the create form
// expanded, the submitted values preserved, and an inline error banner.
func (w *Web) renderNetworksError(rw http.ResponseWriter, r *http.Request, form networkFormState, errMsg string) {
	networks, err := w.store.ListNetworks(r.Context())
	if err != nil {
		w.logger.Error("list networks", "error", err)
		http.Error(rw, "Failed to load networks", http.StatusInternalServerError)
		return
	}
	w.renderForRequestWithStatus(rw, r, http.StatusBadRequest, "networks.html", map[string]any{
		"Active":     "networks",
		"Networks":   networks,
		"Form":       form,
		"Error":      errMsg,
		"ShowCreate": true,
	})
}
