package agent

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/slackhq/nebula/cert"
)

// ReadCertFingerprint reads the host certificate from dataDir and returns its fingerprint.
func ReadCertFingerprint(dataDir string) (string, error) {
	return ReadCertFingerprintAt(filepath.Join(dataDir, "host.crt"))
}

// ReadCertFingerprintAt reads the host certificate from an explicit path.
func ReadCertFingerprintAt(path string) (string, error) {
	certPEM, err := os.ReadFile(path) // #nosec G304 -- operator-controlled certificate path from agent config, documented API contract
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
