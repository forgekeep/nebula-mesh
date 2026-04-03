package pki

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/slackhq/nebula/cert"
)

// SignRequest contains the parameters for signing a host certificate.
type SignRequest struct {
	Name      string
	PublicKey []byte // X25519 public key
	Networks  []netip.Prefix
	Groups    []string
	Duration  time.Duration
}

// Sign creates and signs a host certificate using the CA.
func (m *CAManager) Sign(req SignRequest) (cert.Certificate, error) {
	now := time.Now()

	// Validate CA is not expired
	if m.caCert.Expired(now) {
		return nil, fmt.Errorf("CA certificate is expired")
	}

	notAfter := now.Add(req.Duration)
	// Clamp to CA expiry
	if notAfter.After(m.caCert.NotAfter()) {
		notAfter = m.caCert.NotAfter()
	}

	tbs := &cert.TBSCertificate{
		Version:   cert.Version2,
		Name:      req.Name,
		Networks:  req.Networks,
		Groups:    req.Groups,
		IsCA:      false,
		NotBefore: now,
		NotAfter:  notAfter,
		PublicKey: req.PublicKey,
		Curve:     cert.Curve_CURVE25519,
	}

	c, err := tbs.Sign(m.caCert, cert.Curve_CURVE25519, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	return c, nil
}
