package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"
)

// SigningPublicKeyPEMType is the PEM block type used by the agent for its
// Ed25519 poll-signature public key (ADR 0004 §7.1).
const SigningPublicKeyPEMType = "NEBULA ED25519 PUBLIC KEY"

// SigningPrivateKeyPEMType is the PEM block type used to persist the Ed25519
// signing private key on disk (mode 0600). The block bytes contain the full
// 64-byte ed25519.PrivateKey (seed + public-key half), so SignerFromDisk can
// reconstruct the keypair without re-deriving from a seed.
const SigningPrivateKeyPEMType = "NEBULA ED25519 PRIVATE KEY"

// EnrollResponse is the response from the enrollment endpoint.
type EnrollResponse struct {
	CertificatePEM   string `json:"certificate_pem"`
	CACertificatePEM string `json:"ca_certificate_pem"`
	ConfigYAML       string `json:"config_yaml"`
}

// Reenroll runs the enrollment flow against an existing data directory. It
// is a thin alias of Enroll: the server side decides whether the token is
// fresh (rekey) or bound to an unenrolled host (initial enroll), so the
// agent path is identical. Exposed separately so the cmd-side rekey loop
// reads cleanly.
func Reenroll(serverURL, token, dataDir, signingKeyPath string) error {
	return Enroll(serverURL, token, dataDir, signingKeyPath)
}

// Enroll performs the enrollment flow: generates keypair, sends public key
// to the server with the token, saves received cert and config to dataDir,
// and writes the Ed25519 signing private key to signingKeyPath.
//
// signingKeyPath is intentionally separate from dataDir — Nebula's data dir
// holds Nebula-owned secrets (host.key / host.crt / ca.crt / config.yml),
// while the agent's PoP signing key (ADR 0004) is the agent's concern and
// lives next to agent.yml (default /etc/nebula-agent/host.signing.key). The
// parent directory of signingKeyPath is created with mode 0o755 if missing.
func Enroll(serverURL, token, dataDir, signingKeyPath string) error {
	if signingKeyPath == "" {
		return fmt.Errorf("signingKeyPath is required")
	}
	// Pre-flight: verify both directories are writable BEFORE the POST
	// so a permission error does not burn the single-use enrollment token.
	if err := preflightWritable(dataDir); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	if err := preflightWritable(filepath.Dir(signingKeyPath)); err != nil {
		return fmt.Errorf("signing key dir: %w", err)
	}
	// Generate X25519 keypair (for the Nebula handshake cert).
	privKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privKey); err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}

	// Generate Ed25519 signing keypair (for poll proof-of-possession, ADR 0004).
	signingPub, signingPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing keypair: %w", err)
	}

	// Encode keys to PEM.
	pubKeyPEM := cert.MarshalPublicKeyToPEM(cert.Curve_CURVE25519, pubKey)
	signingPubPEM := pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: signingPub})

	// Send enrollment request
	reqBody, err := json.Marshal(map[string]string{
		"token":                  token,
		"public_key_pem":         string(pubKeyPEM),
		"signing_public_key_pem": string(signingPubPEM),
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

	// Ensure data directory exists. 0o750 — agent owns its cert/key files
	// and no other local user needs to traverse this directory.
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	// Save private key
	privKeyPEM := cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, privKey)
	if err := os.WriteFile(filepath.Join(dataDir, "host.key"), privKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write host key: %w", err)
	}

	// Save signing private key (ADR 0004 — used to sign poll requests).
	// Lives in its own directory, not dataDir; create parent if missing.
	if err := os.MkdirAll(filepath.Dir(signingKeyPath), 0o750); err != nil {
		return fmt.Errorf("create signing key dir: %w", err)
	}
	signingPrivPEM := pem.EncodeToMemory(&pem.Block{Type: SigningPrivateKeyPEMType, Bytes: signingPriv})
	if err := os.WriteFile(signingKeyPath, signingPrivPEM, 0o600); err != nil {
		return fmt.Errorf("write signing key: %w", err)
	}

	// Save certificate
	if err := os.WriteFile(filepath.Join(dataDir, "host.crt"), []byte(enrollResp.CertificatePEM), 0o644); err != nil {
		return fmt.Errorf("write host cert: %w", err)
	}

	// Save CA certificate
	if err := os.WriteFile(filepath.Join(dataDir, "ca.crt"), []byte(enrollResp.CACertificatePEM), 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	// Save config. 0o640 — the agent config may embed enrollment metadata
	// and refresh state; treat as secret-adjacent even though it's not the
	// private key itself.
	if err := os.WriteFile(filepath.Join(dataDir, "config.yml"), []byte(enrollResp.ConfigYAML), 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// preflightWritable verifies dir exists (creating it if missing) and is
// writable by the current process. It writes and removes a temp file
// because Unix permissions alone cannot capture ACL/capability rules.
func preflightWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".nebula-agent-preflight-")
	if err != nil {
		return fmt.Errorf("write test in %s: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return nil
}
