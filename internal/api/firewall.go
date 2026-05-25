package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

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
