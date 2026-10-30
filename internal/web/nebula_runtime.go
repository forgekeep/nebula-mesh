package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/forgekeep/nebula-mesh/internal/configinput"
	"github.com/forgekeep/nebula-mesh/internal/hostdns"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

// nebulaRuntimeView is the host's effective Nebula version as the templates
// show it: the agent's report, else the operator's value, else unknown.
type nebulaRuntimeView struct {
	Known        bool
	Version      string
	SourceLabel  string
	Supported    bool
	MinSupported string
}

func newNebulaRuntimeView(h *models.Host) nebulaRuntimeView {
	view := nebulaRuntimeView{MinSupported: nebulacompat.MinSupported.String()}
	if h == nil {
		return view
	}
	var operator string
	if h.Advanced != nil {
		operator = h.Advanced.NebulaVersion
	}
	version, source := nebulacompat.Effective(h.NebulaVersion, operator)
	switch source {
	case nebulacompat.SourceAgent:
		view.SourceLabel = "reported by agent"
	case nebulacompat.SourceOperator:
		view.SourceLabel = "set by operator"
	default:
		return view
	}
	view.Known = true
	view.Version = version.String()
	view.Supported = version.Supported()
	return view
}

// hostDNSStatusView is the network's experimental split DNS setting as it
// applies to one host.
type hostDNSStatusView struct {
	Settings hostdns.Settings
	Status   nebulacompat.Status
}

// hostDNSView returns nil when the network has no host DNS, or when it cannot
// be read; the host page then omits the row.
func (w *Web) hostDNSView(ctx context.Context, h *models.Host) *hostDNSStatusView {
	raw, err := w.store.GetNetworkConfig(ctx, h.NetworkID, hostdns.StoreKey)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			w.logger.Error("get host dns for host page", "network", h.NetworkID, "error", err)
		}
		return nil
	}
	settings, err := hostdns.Decode(raw)
	if err != nil {
		w.logger.Error("decode host dns for host page", "network", h.NetworkID, "error", err)
		return nil
	}
	if !settings.Enabled() {
		return nil
	}
	var tunDevice string
	if h.Advanced != nil {
		tunDevice = h.Advanced.TunDevice
	}
	return &hostDNSStatusView{Settings: settings, Status: configinput.HostRuntime(h).CheckHostDNS(tunDevice)}
}

// handleHostClearRestartPending lets an operator clear the restart mark on a
// host whose agent cannot see Nebula restart, such as one with no PID file.
func (w *Web) handleHostClearRestartPending(rw http.ResponseWriter, r *http.Request) {
	host, ok := w.loadAccessibleHost(rw, r)
	if !ok {
		return
	}
	op := w.session.CurrentOperator(r)
	if op == nil {
		http.Redirect(rw, r, "/ui/login", http.StatusSeeOther)
		return
	}
	changed, err := w.store.SetHostNebulaRestartPending(r.Context(), host.ID, false, time.Now().UTC())
	if err != nil {
		w.logger.Error("clear restart pending", "host", host.ID, "error", err)
		http.Error(rw, "Failed to update host", http.StatusInternalServerError)
		return
	}
	if changed {
		_ = w.store.AddAuditEntry(r.Context(), op.Username, "host.nebula_restart_pending.changed", host.ID, "state=cleared by operator")
	}
	http.Redirect(rw, r, "/ui/hosts/"+host.ID, http.StatusSeeOther) // #nosec G710 -- same-origin redirect: host.ID is a server-generated UUID, hardcoded /ui/hosts/ prefix keeps Location on the current host
}
