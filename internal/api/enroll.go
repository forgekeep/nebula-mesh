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
	"github.com/juev/nebula-mesh/internal/models"
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
		s.metrics.recordEnrollment(resultDenied)
		writeError(w, http.StatusUnauthorized, "invalid enrollment token")
		return
	}
	if errors.Is(err, store.ErrTokenUsed) {
		s.metrics.recordEnrollment(resultDenied)
		writeError(w, http.StatusConflict, "enrollment token already used")
		return
	}
	if errors.Is(err, store.ErrTokenExpired) {
		s.metrics.recordEnrollment(resultDenied)
		writeError(w, http.StatusGone, "enrollment token expired")
		return
	}
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("consume token", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Get host
	host, err := s.store.GetHost(r.Context(), tok.HostID)
	if errors.Is(err, store.ErrNotFound) {
		s.metrics.recordEnrollment(resultError)
		writeError(w, http.StatusInternalServerError, "host not found")
		return
	}
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("get host for enrollment", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Get network
	network, err := s.store.GetNetwork(r.Context(), host.NetworkID)
	if errors.Is(err, store.ErrNotFound) {
		s.metrics.recordEnrollment(resultError)
		writeError(w, http.StatusInternalServerError, "network not found")
		return
	}
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("get network for enrollment", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Parse public key from PEM
	pubKey, _, _, err := cert.UnmarshalPublicKeyFromPEM([]byte(req.PublicKeyPEM))
	if err != nil {
		s.metrics.recordEnrollment(resultDenied)
		writeError(w, http.StatusBadRequest, "invalid public key PEM")
		return
	}

	hostPrefix, err := buildHostPrefix(host.NebulaIP, network.CIDR)
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("build host prefix", "error", err, "host_ip", host.NebulaIP, "cidr", network.CIDR)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Resolve the CA that owns this host's network and sign with it.
	caMgr, err := s.caForHost(r.Context(), host)
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("resolve host CA", "error", err, "host", host.ID, "ca_id", host.CAID)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}
	hostCert, caCertPEM, err := func() (cert.Certificate, []byte, error) {
		s.caMu.RLock()
		defer s.caMu.RUnlock()

		c, signErr := caMgr.Sign(pki.SignRequest{
			Name:      host.Name,
			PublicKey: pubKey,
			Networks:  []netip.Prefix{hostPrefix},
			Groups:    host.Groups,
			Duration:  30 * 24 * time.Hour, // 30 days
		})
		if signErr != nil {
			return nil, nil, signErr
		}
		ca, caErr := caMgr.CACertPEM()
		if caErr != nil {
			return nil, nil, caErr
		}
		return c, ca, nil
	}()
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("sign certificate", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}
	s.metrics.recordSignature(host.CAID)

	// Post-sign work — no CA lock needed
	certPEM, err := hostCert.MarshalPEM()
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("marshal cert PEM", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	fp, err := hostCert.Fingerprint()
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("cert fingerprint", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Save certificate and enroll host atomically
	if err := s.store.SaveCertificateAndEnrollHost(r.Context(), host.ID, certPEM, fp, hostCert.NotBefore(), hostCert.NotAfter()); err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("save certificate and enroll host", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Pin the freshly-enrolled host to the current network config version so the
	// next agent poll does not redundantly re-send the same config we already
	// embedded in the enrollment response below.
	networkVersion, err := s.store.GetNetworkConfigVersion(r.Context(), host.NetworkID)
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("get network config version", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}
	if err := s.store.UpdateHostConfigVersion(r.Context(), host.ID, networkVersion); err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("update host config version", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	configYAML, err := s.renderHostConfig(r.Context(), host)
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("generate config", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	s.metrics.recordEnrollment(resultOK)
	writeJSON(w, http.StatusOK, enrollResponse{
		CertificatePEM:   string(certPEM),
		CACertificatePEM: string(caCertPEM),
		ConfigYAML:       string(configYAML),
	})
}

// renderHostConfig produces the Nebula config.yml for the given host, resolving
// the network's enrolled lighthouses and applying per-host advanced overrides.
func (s *Server) renderHostConfig(ctx context.Context, host *models.Host) ([]byte, error) {
	lighthouses, err := s.getLighthouses(ctx, host.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("get lighthouses: %w", err)
	}

	input := configgen.GeneratorInput{
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
	}
	if adv := host.Advanced; adv != nil {
		input.PunchyOverride = adv.Punchy
		input.ListenHost = adv.ListenHost
		input.MTU = adv.MTU
		input.TunDevice = adv.TunDevice
		for _, u := range adv.UnsafeRoutes {
			input.UnsafeRoutes = append(input.UnsafeRoutes, configgen.AdvancedUnsafeRoute{Route: u.Route, Via: u.Via})
		}
	}
	return configgen.Generate(input)
}

// getLighthouses returns every enrolled lighthouse in the given network. Pending
// or blocked lighthouses are excluded so peer configs never advertise hosts that
// cannot yet (or no longer) accept traffic.
func (s *Server) getLighthouses(ctx context.Context, networkID string) ([]configgen.LighthouseInfo, error) {
	hosts, err := s.store.ListHosts(ctx, store.HostFilter{
		NetworkID: networkID,
		Status:    models.HostStatusEnrolled,
	})
	if err != nil {
		return nil, err
	}

	result := make([]configgen.LighthouseInfo, 0)
	for _, h := range hosts {
		if !h.IsLighthouse || h.PublicIP == "" {
			continue
		}
		port := h.ListenPort
		if port == 0 {
			port = 4242
		}
		result = append(result, configgen.LighthouseInfo{
			NebulaIP:   h.NebulaIP,
			PublicAddr: fmt.Sprintf("%s:%d", h.PublicIP, port),
		})
	}
	return result, nil
}
