package agent

import (
	"bytes"
	"context"
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

	"github.com/forgekeep/nebula-mesh/internal/keystore"
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
func Reenroll(ctx context.Context, serverURL, token, dataDir, signingKeyPath string) error {
	return Enroll(ctx, serverURL, token, dataDir, signingKeyPath)
}

// enrollmentSecrets collects every heap copy of private key material made
// during enrollment so one deferred wipe covers them all. Fields are filled
// as the corresponding buffers are created; wipe zeroizes whatever has been
// set, matching the server-side standard (caMgr.Wipe, GHSA-8h84 / #181).
type enrollmentSecrets struct {
	privKey        []byte // X25519 private key (32-byte scalar)
	privKeyPEM     []byte // PEM encoding of privKey
	signingPriv    []byte // ed25519.PrivateKey (seed + public half)
	signingPrivPEM []byte // PEM encoding of signingPriv
}

func (s *enrollmentSecrets) wipe() {
	keystore.Zeroize(s.privKey)
	keystore.Zeroize(s.privKeyPEM)
	keystore.Zeroize(s.signingPriv)
	keystore.Zeroize(s.signingPrivPEM)
}

// enrollSecretsObserverForTest, when non-nil, receives the secrets container
// on Enroll's way out, before the deferred wipe runs. Tests use it to alias
// the live buffers and assert they read as zeros after Enroll returns.
// Production code never sets it.
var enrollSecretsObserverForTest func(*enrollmentSecrets)

// Enroll performs the enrollment flow: generates keypair, sends public key
// to the server with the token, saves received cert and config to dataDir,
// and writes the Ed25519 signing private key to signingKeyPath.
//
// signingKeyPath is intentionally separate from dataDir — Nebula's data dir
// holds Nebula-owned secrets (host.key / host.crt / ca.crt / config.yml),
// while the agent's PoP signing key (ADR 0004) is the agent's concern and
// lives next to agent.yml (default /etc/nebula-agent/host.signing.key). The
// parent directory of signingKeyPath is created with mode 0o755 if missing.
func Enroll(ctx context.Context, serverURL, token, dataDir, signingKeyPath string) error {
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
	// Generate X25519 keypair (for the Nebula handshake cert). The private
	// material exists in this function only long enough to reach disk —
	// wipe every heap copy on every return path so the Nebula host key and
	// the PoP signing key don't linger (core dump / swap exposure),
	// matching the server-side zeroization standard (GHSA-8h84, #181).
	secrets := &enrollmentSecrets{}
	defer func() {
		if enrollSecretsObserverForTest != nil {
			enrollSecretsObserverForTest(secrets)
		}
		secrets.wipe()
	}()
	secrets.privKey = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, secrets.privKey); err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	pubKey, err := curve25519.X25519(secrets.privKey, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}

	// Generate Ed25519 signing keypair (for poll proof-of-possession, ADR 0004).
	signingPub, signingPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing keypair: %w", err)
	}
	secrets.signingPriv = signingPriv

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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/enroll", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("build enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Never use http.DefaultClient (no timeout): a connected-but-silent
	// server would hang the enroll/re-enroll path indefinitely (#193).
	client := &http.Client{Timeout: defaultAgentHTTPTimeout}
	resp, err := client.Do(req)
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

	// Save private key. The PEM encoding is a second heap copy of the
	// secret — tracked in secrets and wiped with the raw bytes.
	secrets.privKeyPEM = cert.MarshalPrivateKeyToPEM(cert.Curve_CURVE25519, secrets.privKey)
	if err := os.WriteFile(filepath.Join(dataDir, "host.key"), secrets.privKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write host key: %w", err)
	}

	// Save signing private key (ADR 0004 — used to sign poll requests).
	// Lives in its own directory, not dataDir; create parent if missing.
	if err := os.MkdirAll(filepath.Dir(signingKeyPath), 0o750); err != nil {
		return fmt.Errorf("create signing key dir: %w", err)
	}
	secrets.signingPrivPEM = pem.EncodeToMemory(&pem.Block{Type: SigningPrivateKeyPEMType, Bytes: secrets.signingPriv})
	if err := os.WriteFile(signingKeyPath, secrets.signingPrivPEM, 0o600); err != nil {
		return fmt.Errorf("write signing key: %w", err)
	}

	// Save certificate
	if err := os.WriteFile(filepath.Join(dataDir, "host.crt"), []byte(enrollResp.CertificatePEM), 0o644); err != nil { // #nosec G306 -- host certificate is public PEM material; 0o644 is intentional
		return fmt.Errorf("write host cert: %w", err)
	}

	// Save CA certificate
	if err := os.WriteFile(filepath.Join(dataDir, "ca.crt"), []byte(enrollResp.CACertificatePEM), 0o644); err != nil { // #nosec G306 -- CA certificate is public PEM material; 0o644 is intentional
		return fmt.Errorf("write CA cert: %w", err)
	}

	// Save config. 0o640 — rendered Nebula daemon config (host name,
	// nebula IPs, lighthouse list, firewall rules, paths to key/cert
	// files). No secrets in the file itself; the actual private key
	// lives in host.key, written above at 0o600.
	if err := os.WriteFile(filepath.Join(dataDir, "config.yml"), []byte(enrollResp.ConfigYAML), 0o640); err != nil { // #nosec G306 -- rendered Nebula config: host name, IPs, lighthouse, firewall rules, paths to key/cert files — no secrets; the actual private key is host.key (0o600)
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
