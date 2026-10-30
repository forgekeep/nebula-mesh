package nebulacompat

import (
	"fmt"
	"slices"
	"strings"
)

// Feature is a group of config keys only some Nebula releases or platforms
// understand. Older releases ignore keys they do not know, so gating a
// feature keeps the UI and validation honest rather than keeping Nebula
// starting.
type Feature struct {
	Label string
	Min   Version
	// OSes lists the runtime.GOOS values the feature works on; empty means
	// every OS.
	OSes []string
	// Experimental marks a feature Nebula itself calls experimental.
	Experimental bool
}

var v1_12 = Version{Major: 1, Minor: 12}

// The features nebula-mesh renders only for hosts that can use them.
var (
	FeatureOffloads   = Feature{Label: "UDP and tun offloads", Min: v1_12, OSes: []string{"linux"}}
	FeaturePinThreads = Feature{Label: "thread pinning", Min: v1_12, OSes: []string{"linux"}}
	FeatureLocalAPI   = Feature{Label: "local API control socket", Min: v1_12}
	FeatureHostDNS    = Feature{Label: "host DNS", Min: v1_12, OSes: []string{"darwin", "windows"}, Experimental: true}
)

// Runtime is what the server knows about the Nebula a host runs. The zero
// value is a host with an unknown version and OS, which gets the
// conservative config every supported release understands.
type Runtime struct {
	Version Version
	Source  Source
	// OS is the runtime.GOOS the agent reported; empty when unknown.
	OS string
	// Mobile marks a Mobile Nebula client, which none of the gated features
	// apply to.
	Mobile bool
}

// HostRuntime builds a Runtime from a host's reported version and OS and the
// operator's advanced.nebula_version.
func HostRuntime(reportedVersion, reportedOS, operatorVersion string, mobile bool) Runtime {
	v, src := Effective(reportedVersion, operatorVersion)
	return Runtime{Version: v, Source: src, OS: reportedOS, Mobile: mobile}
}

// Status says whether a feature is rendered for a host and, if not, why.
type Status struct {
	Rendered bool
	// Definite is set when the host cannot use the feature (a known release
	// or OS that lacks it), as opposed to a host whose version is unknown.
	Definite bool
	Reason   string
}

// Check reports whether f is rendered for r. An unknown OS does not exclude
// a feature: Nebula ignores keys meant for another platform.
func (r Runtime) Check(f Feature) Status {
	switch {
	case r.Mobile:
		return Status{Definite: true, Reason: f.Label + " does not apply to mobile clients"}
	case r.OS != "" && len(f.OSes) > 0 && !slices.Contains(f.OSes, r.OS):
		return Status{Definite: true, Reason: fmt.Sprintf("%s requires %s; host reports %s",
			f.Label, strings.Join(f.OSes, " or "), r.OS)}
	case r.Source == SourceUnknown:
		return Status{Reason: fmt.Sprintf("%s requires Nebula %s or newer; the host's Nebula version is unknown",
			f.Label, f.Min)}
	case !r.Version.Supported():
		return Status{Definite: true, Reason: fmt.Sprintf("host runs Nebula %s, below the oldest supported release %s",
			r.Version, MinSupported)}
	case r.Version.Less(f.Min):
		return Status{Definite: true, Reason: fmt.Sprintf("%s requires Nebula %s or newer; host runs %s",
			f.Label, f.Min, r.Version)}
	default:
		return Status{Rendered: true}
	}
}

// CheckHostDNS is Check(FeatureHostDNS) plus the Windows rule: Nebula hands
// tun.dev to the DNS backend as the adapter to configure, and with none set
// it logs an error and leaves host DNS unapplied.
func (r Runtime) CheckHostDNS(tunDevice string) Status {
	st := r.Check(FeatureHostDNS)
	if st.Rendered && r.OS == "windows" && tunDevice == "" {
		return Status{Definite: true, Reason: "host DNS on Windows needs advanced.tun_device to name the adapter"}
	}
	return st
}

// restartKeys are the config keys Nebula reads only at startup, on every OS.
// A SIGHUP leaves their running values alone: 1.12 logs that a restart is
// needed, older releases say nothing. The list comes from Nebula 1.12's
// RestartRequiredIfChanged calls and is applied to every release.
var restartKeys = []string{
	"cipher",
	"dns.identity",
	"firewall.conntrack.routine_cache_timeout",
	"handshakes.query_buffer",
	"handshakes.retries",
	"handshakes.trigger_buffer",
	"handshakes.try_interval",
	"lighthouse.am_lighthouse",
	"listen.host",
	"listen.port",
	"listen.rebind_on_network_change",
	"listen.routines",
	"routines",
	"stats.lighthouse_metrics",
	"stats.message_metrics",
	"timers.connection_alive_interval",
	"timers.pending_deletion_interval",
	"tun.disabled",
	"tun.drop_local_broadcast",
	"tun.drop_multicast",
	"tun.routines",
	"tun.tx_queue",
}

// osRestartKeys are the startup-only keys of one OS.
var osRestartKeys = map[string][]string{
	"darwin":  {"tun.dev", "tun.mtu"},
	"freebsd": {"tun.dev", "tun.mtu"},
	"linux": {
		"listen.batch", "listen.udp_offloads", "tun.cpu_affinity", "tun.dev",
		"tun.pin_threads", "tun.pin_threads_key", "tun.use_offloads",
		"tun.use_system_route_table", "tun.use_system_route_table_buffer_size",
	},
	"windows": {
		"listen.windows_bypass_wdf", "tun.dev", "tun.mtu",
		"tun.network_category", "tun.windows_bypass_wdf",
	},
}

// RestartKeys lists the config keys a reload does not apply on goos.
func RestartKeys(goos string) []string {
	return slices.Concat(restartKeys, osRestartKeys[goos])
}
