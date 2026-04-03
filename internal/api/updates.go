package api

import (
	"context"
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
	if err == store.ErrNotFound {
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
		blocklist = []string{}
	}

	resp := agentUpdatesResponse{
		Blocklist: blocklist,
	}

	// Check if certificate needs renewal
	certInfo, err := s.store.GetCertificateInfo(r.Context(), host.ID)
	if err == nil && pki.ShouldRenew(certInfo.NotBefore, certInfo.NotAfter) {
		s.caMu.RLock()
		newCertPEM, renewErr := s.renewHostCert(r.Context(), host, certInfo)
		var caCertPEM []byte
		if renewErr == nil {
			var certErr error
			caCertPEM, certErr = s.ca.CACertPEM()
			if certErr != nil {
				renewErr = fmt.Errorf("get CA cert PEM: %w", certErr)
			}
		}
		s.caMu.RUnlock()

		if renewErr != nil {
			s.logger.Error("auto-renew cert", "host", host.Name, "error", renewErr)
		} else {
			certStr := string(newCertPEM)
			resp.CertificatePEM = &certStr
			caStr := string(caCertPEM)
			resp.CACertPEM = &caStr
			s.logger.Info("certificate renewed", "host", host.Name)
		}
	}

	resp.HasUpdates = len(blocklist) > 0 || resp.CertificatePEM != nil
	writeJSON(w, http.StatusOK, resp)
}

// renewHostCert re-signs the host certificate with the same public key and fresh expiry.
func (s *Server) renewHostCert(ctx context.Context, host *models.Host, certInfo *models.CertificateInfo) ([]byte, error) {
	// Parse current certificate to get public key
	currentCert, _, err := cert.UnmarshalCertificateFromPEM([]byte(certInfo.PEM))
	if err != nil {
		return nil, fmt.Errorf("parse current cert: %w", err)
	}

	// Get network for prefix
	network, err := s.store.GetNetwork(ctx, host.NetworkID)
	if err != nil {
		return nil, fmt.Errorf("get network: %w", err)
	}

	prefix, err := netip.ParsePrefix(network.CIDR)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR: %w", err)
	}

	hostAddr, err := netip.ParseAddr(host.NebulaIP)
	if err != nil {
		return nil, fmt.Errorf("parse host IP: %w", err)
	}

	// Re-sign with same public key, new expiry
	newCert, err := s.ca.Sign(pki.SignRequest{
		Name:      host.Name,
		PublicKey: currentCert.PublicKey(),
		Networks:  []netip.Prefix{netip.PrefixFrom(hostAddr, prefix.Bits())},
		Groups:    host.Groups,
		Duration:  30 * 24 * time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("sign renewed cert: %w", err)
	}

	certPEM, err := newCert.MarshalPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal cert: %w", err)
	}

	fp, err := newCert.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("fingerprint: %w", err)
	}

	// Save cert and update host fingerprint atomically
	if err := s.store.SaveCertificateAndUpdateHostCert(ctx, host.ID, certPEM, fp, newCert.NotBefore(), newCert.NotAfter()); err != nil {
		return nil, fmt.Errorf("save cert and update host: %w", err)
	}

	return certPEM, nil
}
