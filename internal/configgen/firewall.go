package configgen

import (
	"encoding/json"
	"fmt"
)

// DefaultFirewallInbound and DefaultFirewallOutbound are the baseline policy a
// host receives when its network has no stored firewall rules, or the stored
// rules are unusable: ICMP-only inbound (ping) and allow-all outbound. These
// are the values the management server emitted for every host before
// per-network firewall rules were wired through to generated configs.
var (
	DefaultFirewallInbound  = []FirewallRule{{Port: "any", Proto: "icmp", Group: "any"}}
	DefaultFirewallOutbound = []FirewallRule{{Port: "any", Proto: "any", Group: "any"}}
)

// storedFirewallRules mirrors the JSON the management API persists under the
// network_config "firewall" key.
type storedFirewallRules struct {
	Inbound  []storedFirewallRule `json:"inbound"`
	Outbound []storedFirewallRule `json:"outbound"`
}

type storedFirewallRule struct {
	Port  string `json:"port"`
	Proto string `json:"proto"`
	Group string `json:"group"`
}

// FirewallRulesFromJSON converts the management API's stored firewall JSON
// into generator rules.
//
// It returns the safe defaults together with a nil error when jsonStr is
// empty or declares no rules at all — a network with no policy legitimately
// gets the baseline, which is not an error condition.
//
// It returns the safe defaults together with a non-nil error when the JSON is
// malformed or any rule is unusable (an empty port, proto, or group). The
// empty group in particular is the work-322fy footgun: Nebula rejects a rule
// with neither group nor host, failing the whole config on load. Returning
// the defaults rather than the bad rules guarantees that wiring a network's
// stored policy into a host config can never produce an agent config Nebula
// refuses to load; the non-nil error lets the caller surface that the
// operator's policy is being dropped.
func FirewallRulesFromJSON(jsonStr string) (inbound, outbound []FirewallRule, err error) {
	if jsonStr == "" {
		return DefaultFirewallInbound, DefaultFirewallOutbound, nil
	}
	var stored storedFirewallRules
	if uerr := json.Unmarshal([]byte(jsonStr), &stored); uerr != nil {
		return DefaultFirewallInbound, DefaultFirewallOutbound, fmt.Errorf("parse firewall rules: %w", uerr)
	}
	if len(stored.Inbound) == 0 && len(stored.Outbound) == 0 {
		return DefaultFirewallInbound, DefaultFirewallOutbound, nil
	}
	in, ierr := convertStoredRules("inbound", stored.Inbound)
	if ierr != nil {
		return DefaultFirewallInbound, DefaultFirewallOutbound, ierr
	}
	out, oerr := convertStoredRules("outbound", stored.Outbound)
	if oerr != nil {
		return DefaultFirewallInbound, DefaultFirewallOutbound, oerr
	}
	return in, out, nil
}

func convertStoredRules(direction string, in []storedFirewallRule) ([]FirewallRule, error) {
	out := make([]FirewallRule, 0, len(in))
	for i, r := range in {
		// Mirror the API write-time validation: a rule missing any selector
		// would render a config Nebula rejects (empty group/host) or an
		// ambiguous match (empty port/proto).
		if r.Port == "" || r.Proto == "" || r.Group == "" {
			return nil, fmt.Errorf("%s rule %d: port, proto, and group must all be non-empty", direction, i)
		}
		// storedFirewallRule and FirewallRule share the same field layout;
		// the conversion drops only the json tags.
		out = append(out, FirewallRule(r))
	}
	return out, nil
}
