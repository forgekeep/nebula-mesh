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
	// UnsafeNetworks are the non-overlay prefixes this host is authorized to
	// route for. Nebula enforces routing on the certificate, not on config: a
	// gateway whose cert omits the prefix silently refuses to route it, and
	// both ends drop the traffic in Firewall.Drop before any rule is consulted
	// (the local address is not in routableNetworks). Empty for ordinary hosts.
	UnsafeNetworks []netip.Prefix
	Groups         []string
	Duration       time.Duration
	// Now sets the certificate's NotBefore (and the CA-expiry check instant).
	// Zero means time.Now(). Callers holding an injectable clock pass it so
	// re-signs under simulated time produce distinct, correctly-dated certs.
	Now time.Time
}

// Sign creates and signs a host certificate using the CA.
func (m *CAManager) Sign(req SignRequest) (cert.Certificate, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}

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
		Version:        cert.Version2,
		Name:           req.Name,
		Networks:       req.Networks,
		UnsafeNetworks: req.UnsafeNetworks,
		Groups:         req.Groups,
		IsCA:           false,
		NotBefore:      now,
		NotAfter:       notAfter,
		PublicKey:      req.PublicKey,
		Curve:          cert.Curve_CURVE25519,
	}

	c, err := tbs.Sign(m.caCert, cert.Curve_CURVE25519, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}

	return c, nil
}
