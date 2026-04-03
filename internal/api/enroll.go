package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/juev/nebula-mesh/internal/configgen"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
	"github.com/slackhq/nebula/cert"
)

type enrollRequest struct {
	Token        string `json:"token"`
	PublicKeyPEM string `json:"public_key_pem"`
}

type enrollResponse struct {
	CertificatePEM   string `json:"certificate_pem"`
	CACertificatePEM string `json:"ca_certificate_pem"`
	ConfigYAML       string `json:"config_yaml"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Token == "" || req.PublicKeyPEM == "" {
		writeError(w, http.StatusBadRequest, "token and public_key_pem are required")
		return
	}

	// Consume token (validates one-time use and expiry)
	tok, err := s.store.ConsumeToken(r.Context(), req.Token)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	if errors.Is(err, store.ErrTokenUsed) {
		writeError(w, http.StatusConflict, "enrollment token already used")
		return
	}
	if errors.Is(err, store.ErrTokenExpired) {
		writeError(w, http.StatusGone, "enrollment token expired")
		return
	}
	if err != nil {
		s.logger.Error("consume token", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Get host
	host, err := s.store.GetHost(r.Context(), tok.HostID)
	if err != nil {
		s.logger.Error("get host for enrollment", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Get network
	network, err := s.store.GetNetwork(r.Context(), host.NetworkID)
	if err != nil {
		s.logger.Error("get network for enrollment", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Parse public key from PEM
	pubKey, _, _, err := cert.UnmarshalPublicKeyFromPEM([]byte(req.PublicKeyPEM))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid public key PEM")
		return
	}

	// Parse CIDR to get prefix length
	prefix, err := netip.ParsePrefix(network.CIDR)
	if err != nil {
		s.logger.Error("parse network CIDR", "error", err, "cidr", network.CIDR)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Build host IP with network prefix
	hostAddr, err := netip.ParseAddr(host.NebulaIP)
	if err != nil {
		s.logger.Error("parse host IP", "error", err, "ip", host.NebulaIP)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}
	hostPrefix := netip.PrefixFrom(hostAddr, prefix.Bits())

	// CA operations — lock needed only for Sign + CACertPEM
	s.caMu.RLock()
	hostCert, err := s.ca.Sign(pki.SignRequest{
		Name:      host.Name,
		PublicKey: pubKey,
		Networks:  []netip.Prefix{hostPrefix},
		Groups:    host.Groups,
		Duration:  30 * 24 * time.Hour, // 30 days
	})
	if err != nil {
		s.caMu.RUnlock()
		s.logger.Error("sign certificate", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}
	caCertPEM, err := s.ca.CACertPEM()
	s.caMu.RUnlock()
	if err != nil {
		s.logger.Error("get CA cert PEM", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Post-sign work — no CA lock needed
	certPEM, err := hostCert.MarshalPEM()
	if err != nil {
		s.logger.Error("marshal cert PEM", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	fp, err := hostCert.Fingerprint()
	if err != nil {
		s.logger.Error("cert fingerprint", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Save certificate and enroll host atomically
	if err := s.store.SaveCertificateAndEnrollHost(r.Context(), host.ID, certPEM, fp, hostCert.NotBefore(), hostCert.NotAfter()); err != nil {
		s.logger.Error("save certificate and enroll host", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Get lighthouses for config
	lighthouses, err := s.getLighthouses(r.Context(), host.NetworkID)
	if err != nil {
		s.logger.Error("get lighthouses", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Generate config
	configYAML, err := configgen.Generate(configgen.GeneratorInput{
		HostName:     host.Name,
		NebulaIP:     host.NebulaIP,
		IsLighthouse: host.IsLighthouse,
		IsRelay:      host.IsRelay,
		CACertPath:   "/etc/nebula/ca.crt",
		CertPath:     "/etc/nebula/host.crt",
		KeyPath:      "/etc/nebula/host.key",
		ListenPort:   host.ListenPort,
		Lighthouses:  lighthouses,
		FirewallInbound: []configgen.FirewallRule{
			{Port: "any", Proto: "icmp", Group: "any"},
		},
		FirewallOutbound: []configgen.FirewallRule{
			{Port: "any", Proto: "any", Group: "any"},
		},
	})
	if err != nil {
		s.logger.Error("generate config", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	writeJSON(w, http.StatusOK, enrollResponse{
		CertificatePEM:   string(certPEM),
		CACertificatePEM: string(caCertPEM),
		ConfigYAML:       string(configYAML),
	})
}

func (s *Server) getLighthouses(ctx context.Context, networkID string) ([]configgen.LighthouseInfo, error) {
	hosts, err := s.store.ListHosts(ctx, store.HostFilter{NetworkID: networkID})
	if err != nil {
		return nil, err
	}

	var result []configgen.LighthouseInfo
	for _, h := range hosts {
		if h.IsLighthouse && h.PublicIP != "" {
			port := h.ListenPort
			if port == 0 {
				port = 4242
			}
			result = append(result, configgen.LighthouseInfo{
				NebulaIP:   h.NebulaIP,
				PublicAddr: fmt.Sprintf("%s:%d", h.PublicIP, port),
			})
		}
	}
	return result, nil
}
