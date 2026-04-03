package agent

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/slackhq/nebula/cert"
)

// ReadCertFingerprint reads the host certificate from dataDir and returns its fingerprint.
func ReadCertFingerprint(dataDir string) (string, error) {
	certPEM, err := os.ReadFile(filepath.Join(dataDir, "host.crt"))
	if err != nil {
		return "", fmt.Errorf("read host certificate: %w", err)
	}

	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	fp, err := c.Fingerprint()
	if err != nil {
		return "", fmt.Errorf("certificate fingerprint: %w", err)
	}

	return fp, nil
}
