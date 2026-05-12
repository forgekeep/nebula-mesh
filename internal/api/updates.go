package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"time"

	"github.com/juev/nebula-mesh/internal/models"
	"github.com/juev/nebula-mesh/internal/pki"
	"github.com/juev/nebula-mesh/internal/store"
	"github.com/slackhq/nebula/cert"
)

type agentUpdatesResponse struct {
	HasUpdates     bool     `json:"has_updates"`
	CertificatePEM *string  `json:"certificate_pem,omitempty"`
	CACertPEM      *string  `json:"ca_certificate_pem,omitempty"`
	ConfigYAML     *string  `json:"config_yaml,omitempty"`
	Blocklist      []string `json:"blocklist"`
}

func (s *Server) handleAgentUpdates(w http.ResponseWriter, r *http.Request) {
	fingerprint := r.URL.Query().Get("fingerprint")
	if fingerprint == "" {
		writeError(w, http.StatusBadRequest, "fingerprint query parameter is required")
		return
	}

	host, err := s.store.GetHostByFingerprint(r.Context(), fingerprint)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.logger.Error("get host by fingerprint", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get host")
		return
	}

	// non-critical: log and continue — last_seen is informational
	now := time.Now()
	if err := s.store.UpdateHostLastSeen(r.Context(), host.ID, now); err != nil {
		s.logger.Error("update last seen", "error", err)
	}

	// Get blocklist
	blocklist, err := s.store.GetBlocklist(r.Context())
	if err != nil {
		s.logger.Error("get blocklist", "error", err)
		writeError(w, http.StatusInternalServerError, "failed to get blocklist")
		return
	}

	resp := agentUpdatesResponse{
		Blocklist: blocklist,
	}

	// Check if certificate needs renewal
	certInfo, err := s.store.GetCertificateInfo(r.Context(), host.ID)
	if err == nil && pki.ShouldRenew(certInfo.NotBefore, certInfo.NotAfter) {
		signed, renewErr := s.signHostCert(r.Context(), host, certInfo)

		if renewErr != nil {
			s.metrics.recordRenewal(resultError)
			s.logger.Error("auto-renew cert", "host", host.Name, "error", renewErr)
		} else {
			s.metrics.recordSignature(host.CAID)
			// Save outside CA lock — DB I/O does not need CA access
			if saveErr := s.store.SaveCertificateAndUpdateHostCert(r.Context(), host.ID, signed.certPEM, signed.fp, signed.notBefore, signed.notAfter); saveErr != nil {
				s.metrics.recordRenewal(resultError)
				s.logger.Error("save renewed cert", "host", host.Name, "error", saveErr)
				writeError(w, http.StatusInternalServerError, "failed to save renewed certificate")
				return
			}
			s.metrics.recordRenewal(resultOK)
			certStr := string(signed.certPEM)
			resp.CertificatePEM = &certStr
			caStr := string(signed.caCertPEM)
			resp.CACertPEM = &caStr
			s.logger.Info("certificate renewed", "host", host.Name)
		}
	}

	// Check if the network config version moved since this host's last poll.
	// If it did, re-render the Nebula config with the current lighthouse list
	// (and any other network-level config) and ship it to the agent.
	netVersion, verErr := s.store.GetNetworkConfigVersion(r.Context(), host.NetworkID)
	if verErr != nil {
		s.logger.Error("get network config version", "error", verErr)
	} else {
		hostVersion, hvErr := s.store.GetHostConfigVersion(r.Context(), host.ID)
		if hvErr != nil {
			s.logger.Error("get host config version", "error", hvErr)
		} else if hostVersion != netVersion {
			configYAML, cfgErr := s.renderHostConfig(r.Context(), host)
			if cfgErr != nil {
				s.logger.Error("render host config", "host", host.Name, "error", cfgErr)
			} else {
				if uvErr := s.store.UpdateHostConfigVersion(r.Context(), host.ID, netVersion); uvErr != nil {
					s.logger.Error("update host config version", "host", host.Name, "error", uvErr)
				} else {
					cfgStr := string(configYAML)
					resp.ConfigYAML = &cfgStr
					s.logger.Info("config rolled out", "host", host.Name, "from_version", hostVersion, "to_version", netVersion)
				}
			}
		}
	}

	resp.HasUpdates = len(blocklist) > 0 || resp.CertificatePEM != nil || resp.ConfigYAML != nil
	writeJSON(w, http.StatusOK, resp)
}

// signResult holds the output of signing a host certificate.
type signResult struct {
	certPEM   []byte
	fp        string
	notBefore time.Time
	notAfter  time.Time
	caCertPEM []byte
}

// signHostCert re-signs the host certificate with the same public key and fresh expiry.
// CA lock is held only during crypto operations (Sign + CACertPEM).
func (s *Server) signHostCert(ctx context.Context, host *models.Host, certInfo *models.CertificateInfo) (*signResult, error) {
	// Prep work — no CA lock needed
	currentCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(certInfo.PEM))
	if err != nil {
		return nil, fmt.Errorf("parse current cert: %w", err)
	}
	if len(currentCert.PublicKey()) == 0 {
		return nil, fmt.Errorf("current certificate has empty public key")
	}

	network, err := s.store.GetNetwork(ctx, host.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}

	hostPrefix, err := buildHostPrefix(host.NebulaIP, network.CIDR)
	if err != nil {
		return nil, err
	}

	caMgr, err := s.caForHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve host CA: %w", err)
	}
	// CA operations — lock needed only for Sign + CACertPEM
	newCert, caCertPEM, caErr := func() (cert.Certificate, []byte, error) {
		s.caMu.RLock()
		defer s.caMu.RUnlock()

		c, signErr := caMgr.Sign(pki.SignRequest{
			Name:      host.Name,
			PublicKey: currentCert.PublicKey(),
			Networks:  []netip.Prefix{hostPrefix},
			Groups:    host.Groups,
			Duration:  30 * 24 * time.Hour,
		})
		if signErr != nil {
			return nil, nil, fmt.Errorf("sign renewed cert: %w", signErr)
		}
		ca, err := caMgr.CACertPEM()
		if err != nil {
			return nil, nil, fmt.Errorf("get CA cert PEM: %w", err)
		}
		return c, ca, nil
	}()
	if caErr != nil {
		return nil, caErr
	}

	// Post-sign work — no CA lock needed
	certPEM, err := newCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal cert: %w", err)
	}

	fp, err := newCert.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}

	return &signResult{
		certPEM:   certPEM,
		fp:        fp,
		notBefore: newCert.NotBefore(),
		notAfter:  newCert.NotAfter(),
		caCertPEM: caCertPEM,
	}, nil
}
