package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/forgekeep/nebula-mesh/internal/models"
)

// parseAdvancedFromForm reads the `adv_*` form fields from the host
// creation form and returns a *HostAdvanced (or nil if nothing was set).
// All fields are optional; an empty form returns nil so default rendering
// remains untouched.
func parseAdvancedFromForm(r *http.Request) (*models.HostAdvanced, error) {
	adv := &models.HostAdvanced{}
	used := false

	if h := strings.TrimSpace(r.FormValue("adv_listen_host")); h != "" {
		adv.ListenHost = h
		used = true
	}
	if m := strings.TrimSpace(r.FormValue("adv_mtu")); m != "" {
		v, err := strconv.Atoi(m)
		if err != nil {
			return nil, fmt.Errorf("adv_mtu must be a number")
		}
		adv.MTU = v
		used = true
	}
	if d := strings.TrimSpace(r.FormValue("adv_tun_device")); d != "" {
		adv.TunDevice = d
		used = true
	}
	switch r.FormValue("adv_punchy") {
	case "true":
		v := true
		adv.Punchy = &v
		used = true
	case "false":
		v := false
		adv.Punchy = &v
		used = true
	}
	switch r.FormValue("adv_punchy_respond") {
	case "true":
		v := true
		adv.PunchyRespond = &v
		used = true
	case "false":
		v := false
		adv.PunchyRespond = &v
		used = true
	}
	if raw := strings.TrimSpace(r.FormValue("adv_unsafe_routes")); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 3 || parts[1] != "via" {
				return nil, fmt.Errorf("adv_unsafe_routes line %q: expected '<CIDR> via <NEBULA_IP>'", line)
			}
			adv.UnsafeRoutes = append(adv.UnsafeRoutes, models.UnsafeRoute{Route: parts[0], Via: parts[2]})
			used = true
		}
	}
	if raw := strings.TrimSpace(r.FormValue("adv_firewall_inbound")); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			rule, err := parseFirewallInboundLine(line)
			if err != nil {
				return nil, err
			}
			adv.FirewallInbound = append(adv.FirewallInbound, rule)
			used = true
		}
	}

	if !used {
		return nil, nil
	}
	return adv, nil
}

// firewallInboundSyntax is the one-line grammar the host form accepts for a
// per-host inbound rule. The peer is selected either by group (`from web`) or
// by prefix (`cidr=10.0.0.0/24`) — never both, since Nebula OR's the two —
// and `local_cidr=` optionally narrows the local address, which is what makes
// a rule apply to prefixes served via unsafe_routes.
const firewallInboundSyntax = `'<PORT>/<PROTO> from <GROUP>' with optional 'cidr=<CIDR>' / 'local_cidr=<CIDR>' clauses`

// isFirewallClause reports whether a field is one of the keyed clauses rather
// than a bare value such as a group name.
func isFirewallClause(field string) bool {
	return strings.HasPrefix(field, "cidr=") || strings.HasPrefix(field, "local_cidr=")
}

// parseFirewallInboundLine parses one line of the adv_firewall_inbound
// textarea. Accepted forms:
//
//	443/tcp from web
//	443/tcp from web local_cidr=10.10.0.5/32
//	443/tcp cidr=192.168.50.0/24
//	any/icmp from any local_cidr=any
func parseFirewallInboundLine(line string) (models.HostFirewallRule, error) {
	fail := func() (models.HostFirewallRule, error) {
		return models.HostFirewallRule{}, fmt.Errorf("adv_firewall_inbound line %q: expected %s", line, firewallInboundSyntax)
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return fail()
	}
	port, proto, _ := strings.Cut(fields[0], "/")
	if port == "" || proto == "" || strings.Contains(proto, "/") {
		return fail()
	}
	rule := models.HostFirewallRule{Port: port, Proto: proto}
	for i := 1; i < len(fields); i++ {
		switch field := fields[i]; {
		case field == "from":
			// `from` takes the next field as the group name. Reject a clause
			// keyword there: `from cidr=10.0.0.0/24` is a plausible way to
			// mistype the prefix selector, and consuming it as a group name
			// would silently define a group called "cidr=10.0.0.0/24" that no
			// certificate can ever carry — a rule that matches nothing.
			if i+1 >= len(fields) || rule.Group != "" || isFirewallClause(fields[i+1]) {
				return fail()
			}
			i++
			rule.Group = fields[i]
		case strings.HasPrefix(field, "cidr="):
			if rule.Cidr != "" {
				return fail()
			}
			rule.Cidr = strings.TrimPrefix(field, "cidr=")
		case strings.HasPrefix(field, "local_cidr="):
			if rule.LocalCidr != "" {
				return fail()
			}
			rule.LocalCidr = strings.TrimPrefix(field, "local_cidr=")
		default:
			return fail()
		}
	}
	// Surface the selector rules here, where the offending line can be named,
	// rather than letting model validation report a bare field index.
	if err := models.ValidateFirewallSelectors(rule.Group, rule.Cidr); err != nil {
		return models.HostFirewallRule{}, fmt.Errorf("adv_firewall_inbound line %q: %w", line, err)
	}
	return rule, nil
}
