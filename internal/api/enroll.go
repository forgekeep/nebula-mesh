package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/configgen"
	"github.com/forgekeep/nebula-mesh/internal/models"
	"github.com/forgekeep/nebula-mesh/internal/pki"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

type enrollRequest struct {
	Token         string `json:"token"`
	PublicKeyPEM  string `json:"public_key_pem"`
	SigningPubPEM string `json:"signing_public_key_pem"`
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
	if _, err := decodeSigningPublicKeyPEM(req.SigningPubPEM); err != nil {
		s.metrics.recordEnrollment(resultDenied)
		writeError(w, http.StatusBadRequest, "signing_public_key_pem is required and must be Ed25519")
		return
	}

	// Resolve + validate the token (one-time use, expiry) WITHOUT consuming it
	// yet. The single-use consume happens atomically with the cert save in
	// ConsumeTokenAndEnrollHost below, so a failure mid-enrollment does not burn
	// the token (#8c enrollment-token rollback atomicity).
	tok, err := s.store.GetEnrollmentToken(r.Context(), req.Token)
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

	// Durable revocation (GHSA-339v-266x-79xr): refuse to (re-)issue a cert for
	// a blocked host or one whose owning operator is disabled. This closes the
	// re-enroll bypass, where a fresh fingerprint would otherwise sidestep the
	// fingerprint-keyed blocklist that is only consulted at poll time.
	if err := s.checkIssuanceAllowed(r.Context(), host); err != nil {
		switch {
		case errors.Is(err, errHostBlocked), errors.Is(err, errOperatorDisabled):
			s.metrics.recordEnrollment(resultDenied)
			s.logger.Warn("enrollment denied", "host", host.ID, "reason", err.Error())
			writeError(w, http.StatusForbidden, "enrollment denied: "+err.Error())
		default:
			s.metrics.recordEnrollment(resultError)
			s.logger.Error("issuance check", "error", err, "host", host.ID)
			writeError(w, http.StatusInternalServerError, "enrollment failed")
		}
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

	prefixes, err := buildHostPrefixes(network, host.NebulaIPs)
	if err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("build host prefixes", "error", err, "host_id", host.ID)
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
	defer caMgr.Wipe() // GHSA-8h84-fhqq-q58v: zeroise plaintext CA key on return.
	hostCert, caCertPEM, err := func() (cert.Certificate, []byte, error) {
		c, signErr := caMgr.Sign(pki.SignRequest{
			Name:      host.Name,
			PublicKey: pubKey,
			Networks:  prefixes,
			Groups:    host.Groups,
			Duration:  pki.DefaultAgentCertDuration,
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

	// Atomically consume the single-use token and enroll the host with its
	// freshly-signed cert. Consuming here (rather than up front) means a
	// transient failure during signing leaves the token usable for retry; a
	// concurrent enrollment that already consumed it loses the CAS and gets 409.
	if err := s.store.ConsumeTokenAndEnrollHost(r.Context(), host.ID, req.Token, certPEM, fp, hostCert.NotBefore(), hostCert.NotAfter()); err != nil {
		if errors.Is(err, store.ErrTokenUsed) {
			s.metrics.recordEnrollment(resultDenied)
			writeError(w, http.StatusConflict, "enrollment token already used")
			return
		}
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("consume token and enroll host", "error", err)
		writeError(w, http.StatusInternalServerError, "enrollment failed")
		return
	}

	// Bind the Ed25519 signing public key to the host so subsequent poll
	// signatures verify against it (ADR 0004 §7.1).
	if err := s.store.UpdateHostSigningPub(r.Context(), host.ID, req.SigningPubPEM); err != nil {
		s.metrics.recordEnrollment(resultError)
		s.logger.Error("update host signing pub", "error", err)
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
	s.emit("host.enrolled", map[string]any{
		"host_id":     host.ID,
		"host_name":   host.Name,
		"network_id":  host.NetworkID,
		"ca_id":       host.CAID,
		"fingerprint": fp,
	})
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

	// Validate family-match for unsafe_routes
	if adv := host.Advanced; adv != nil {
		for _, u := range adv.UnsafeRoutes {
			routePrefix, err := netip.ParsePrefix(u.Route)
			if err != nil {
				return nil, fmt.Errorf("parse route %q: %w", u.Route, err)
			}
			viaAddr, err := netip.ParseAddr(u.Via)
			if err != nil {
				return nil, fmt.Errorf("parse via %q: %w", u.Via, err)
			}

			// Check family match between route and via
			if routePrefix.Addr().Is4() != viaAddr.Is4() {
				family := "IPv6"
				if routePrefix.Addr().Is4() {
					family = "IPv4"
				}
				return nil, fmt.Errorf("unsafe_route family mismatch: route %s (requires %s via address) but via %s uses different family", u.Route, family, u.Via)
			}

			// Check that host has at least one address in the same family as via
			hasFamily := false
			for _, addr := range host.NebulaIPs {
				hostAddr, _ := netip.ParseAddr(addr)
				if hostAddr.Is4() == viaAddr.Is4() {
					hasFamily = true
					break
				}
			}
			if !hasFamily {
				family := "IPv6"
				if viaAddr.Is4() {
					family = "IPv4"
				}
				return nil, fmt.Errorf("unsafe_route family mismatch: route %s needs %s host address but host %q has no %s addresses", u.Route, family, host.Name, family)
			}
		}
	}

	fwInbound, fwOutbound := s.firewallRulesForGenerator(ctx, host.NetworkID)

	input := configgen.GeneratorInput{
		HostName:         host.Name,
		NebulaIPs:        host.NebulaIPs,
		IsLighthouse:     host.IsLighthouse,
		IsRelay:          host.IsRelay,
		CACertPath:       "/etc/nebula/ca.crt",
		CertPath:         "/etc/nebula/host.crt",
		KeyPath:          "/etc/nebula/host.key",
		ListenPort:       host.ListenPort,
		Lighthouses:      lighthouses,
		FirewallInbound:  fwInbound,
		FirewallOutbound: fwOutbound,
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
		if len(h.NebulaIPs) == 0 {
			continue
		}
		port := h.ListenPort
		if port == 0 {
			port = 4242
		}
		result = append(result, configgen.LighthouseInfo{
			NebulaIPs:  h.NebulaIPs,
			PublicAddr: fmt.Sprintf("%s:%d", h.PublicIP, port),
		})
	}
	return result, nil
}
