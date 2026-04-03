package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// EnrollResponse is the response from the enrollment endpoint.
type EnrollResponse struct {
	CertificatePEM   string `json:"certificate_pem"`
	CACertificatePEM string `json:"ca_certificate_pem"`
	ConfigYAML       string `json:"config_yaml"`
}

// Enroll performs the enrollment flow: generates keypair, sends public key
// to the server with the token, saves received cert and config to dataDir.
func Enroll(serverURL, token, dataDir string) error {
	// Generate X25519 keypair
	privKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privKey); err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}

	// Encode public key to PEM
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey)

	// Send enrollment request
	reqBody, err := json.Marshal(map[string]string{
		"token":          token,
		"public_key_pem": string(pubKeyPEM),
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := http.Post(serverURL+"/api/v1/enroll", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("enrollment request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("enrollment failed (HTTP %d, body unreadable: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("enrollment failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var enrollResp EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return fmt.Errorf("decode enrollment response: %w", err)
	}

	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Save private key
	privKeyPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, privKey)
	if err := os.WriteFile(filepath.Join(dataDir, "host.key"), privKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write host key: %w", err)
	}

	// Save certificate
	if err := os.WriteFile(filepath.Join(dataDir, "host.crt"), []byte(enrollResp.CertificatePEM), 0o644); err != nil {
		return fmt.Errorf("write host cert: %w", err)
	}

	// Save CA certificate
	if err := os.WriteFile(filepath.Join(dataDir, "ca.crt"), []byte(enrollResp.CACertificatePEM), 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	// Save config
	if err := os.WriteFile(filepath.Join(dataDir, "config.yml"), []byte(enrollResp.ConfigYAML), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}
