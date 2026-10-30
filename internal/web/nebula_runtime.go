package web

import (
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/nebulacompat"
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
