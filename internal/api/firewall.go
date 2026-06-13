package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type firewallRulesRequest struct {
	Inbound  []firewallRule `json:"inbound"`
	Outbound []firewallRule `json:"outbound"`
}

type firewallRule struct {
	Port  string `json:"port"`
	Proto string `json:"proto"`
	Group string `json:"group"`
}

var defaultFirewallRules = firewallRulesRequest{
	Inbound:  []firewallRule{{Port: "any", Proto: "icmp", Group: "any"}},
	Outbound: []firewallRule{{Port: "any", Proto: "any", Group: "any"}},
}

func (s *Server) handleGetFirewall(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")

	network, err := s.store.GetNetwork(r.Context(), networkID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	if err != nil {
		s.logger.Error("get network for firewall", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load network")
		return
	}
	ok, err := s.canAccessNetwork(r.Context(), network)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	rules, err := s.getFirewallRules(r, networkID)
	if err != nil {
		s.logger.Error("get firewall rules", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get firewall rules")
		return
	}

	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleUpdateFirewall(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")

	network, err := s.store.GetNetwork(r.Context(), networkID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	if err != nil {
		s.logger.Error("get network for firewall update", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to load network")
		return
	}
	ok, err := s.canAccessNetwork(r.Context(), network)
	if err != nil {
		s.logger.Error("authz check", "error", err)
		writeError(w, http.StatusInternalServerError, "authz check failed")
		return
	}
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}

	var req firewallRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	for _, rules := range [][]firewallRule{req.Inbound, req.Outbound} {
		for _, rule := range rules {
			if rule.Port == "" {
				writeError(w, http.StatusBadRequest, "firewall rule port must not be empty")
				return
			}
			if rule.Proto == "" {
				writeError(w, http.StatusBadRequest, "firewall rule proto must not be empty")
				return
			}
			// A rule without a target group is marshaled into network_config and
			// pushed to every agent, where Nebula treats the empty selector as
			// match-any — a broader allow than intended. Require an explicit
			// selector and bound its length, consistent with host group caps.
			if rule.Group == "" {
				writeError(w, http.StatusBadRequest, "firewall rule must specify a target group")
				return
			}
			if len(rule.Group) > maxGroupNameLen {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("firewall rule group must be at most %d characters", maxGroupNameLen))
				return
			}
		}
	}

	rulesJSON, err := json.Marshal(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to marshal rules")
		return
	}
	if err := s.store.SetNetworkConfigAndBumpVersion(r.Context(), networkID, "firewall", string(rulesJSON)); err != nil {
		s.logger.Error("set firewall rules", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update firewall rules")
		return
	}

	s.logger.Info("firewall rules updated", "network", networkID)
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) getFirewallRules(r *http.Request, networkID string) (*firewallRulesRequest, error) {
	val, err := s.store.GetNetworkConfig(r.Context(), networkID, "firewall")
	if errors.Is(err, store.ErrNotFound) {
		rules := defaultFirewallRules
		return &rules, nil
	}
	if err != nil {
		return nil, err
	}

	var rules firewallRulesRequest
	if err := json.Unmarshal([]byte(val), &rules); err != nil {
		return nil, fmt.Errorf("unmarshal firewall rules: %w", err)
	}
	return &rules, nil
}

// firewallRulesForGenerator resolves the network's stored firewall policy into
// generator rules for renderHostConfig. A network with no stored policy gets
// the safe baseline (ICMP inbound / allow-all outbound). A stored policy that
// is unusable — malformed, or a rule missing a selector that would render a
// config Nebula rejects — also falls back to the baseline, logged at Warn so
// the operator can see their policy is not being applied rather than having
// agents silently fail to load config.
func (s *Server) firewallRulesForGenerator(ctx context.Context, networkID string) (inbound, outbound []configgen.FirewallRule) {
	val, err := s.store.GetNetworkConfig(ctx, networkID, "firewall")
	if errors.Is(err, store.ErrNotFound) {
		return configgen.DefaultFirewallInbound, configgen.DefaultFirewallOutbound
	}
	if err != nil {
		s.logger.Error("load firewall rules; using default baseline", "network", networkID, "error", err)
		return configgen.DefaultFirewallInbound, configgen.DefaultFirewallOutbound
	}
	in, out, ferr := configgen.FirewallRulesFromJSON(val)
	if ferr != nil {
		s.logger.Warn("network firewall policy unusable; agents get the default baseline (icmp inbound / allow-all outbound)",
			"network", networkID, "error", ferr)
	}
	return in, out
}
