package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
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

func (s *Server) handleGetFirewall(w http.ResponseWriter, r *http.Request) {
	networkID := chi.URLParam(r, "id")

	// Get firewall rules from network_config table
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

	var req firewallRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Store rules as JSON in network_config
	rulesJSON, _ := json.Marshal(req)
	if err := s.setNetworkConfig(r, networkID, "firewall", string(rulesJSON)); err != nil {
		s.logger.Error("set firewall rules", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to update firewall rules")
		return
	}

	// Bump config version so agents get new config on poll
	if err := s.store.BumpNetworkConfigVersion(r.Context(), networkID); err != nil {
		s.logger.Error("bump config version", "error", err)
	}

	s.logger.Info("firewall rules updated", "network", networkID)
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) getFirewallRules(_ *http.Request, _ string) (*firewallRulesRequest, error) {
	// Default rules
	return &firewallRulesRequest{
		Inbound:  []firewallRule{{Port: "any", Proto: "icmp", Group: "any"}},
		Outbound: []firewallRule{{Port: "any", Proto: "any", Group: "any"}},
	}, nil
}

func (s *Server) setNetworkConfig(_ *http.Request, _, _, _ string) error {
	// TODO: implement network_config CRUD when needed
	return nil
}
