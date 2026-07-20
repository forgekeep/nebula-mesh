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
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
	"golang.org/x/crypto/curve25519"

	"github.com/forgekeep/nebula-mesh/internal/fsutil"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/models"
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
	ConfigVersion    int    `json:"config_version,omitempty"`
}

// ReenrollOptions preserves the resolved paths of an existing agent during a
// server-requested rekey.
type ReenrollOptions struct {
	DataDir        string
	SigningKeyPath string
	PIDFile        string
	Profile        models.AgentProfile
}

// Reenroll replaces an existing agent identity using its current profile.
func Reenroll(ctx context.Context, serverURL, token string, options ReenrollOptions) error {
	return reenrollWithSignal(ctx, serverURL, token, options, signalNebulaFromPID)
}

func reenrollWithSignal(
	ctx context.Context,
	serverURL, token string,
	options ReenrollOptions,
	signal func(string) error,
) error {
	var reload func() error
	if options.PIDFile != "" {
		reload = func() error { return signal(options.PIDFile) }
	}
	return enrollWithProfile(ctx, serverURL, token, options.DataDir, options.SigningKeyPath, options.Profile, reload)
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
// to the server with the token, saves received cert (and CA cert) to dataDir,
// writes the rendered Nebula config to nebulaConfigPath, and writes the
// Ed25519 signing private key to signingKeyPath.
//
// nebulaConfigPath is the path Nebula actually reads its config from; an empty
// value falls back to dataDir/config.yml for backward compatibility. Honoring
// it keeps the initial enroll write and the running daemon's rewrites pointed
// at the same file (#224); the daemon resolves the same path in poller.go.
//
// signingKeyPath is intentionally separate from dataDir — Nebula's data dir
// holds Nebula-owned secrets (host.key / host.crt / ca.crt / config.yml),
// while the agent's PoP signing key (ADR 0004) is the agent's concern and
// lives next to agent.yml (default /etc/nebula-agent/host.signing.key). The
// parent directory of signingKeyPath is created with mode 0o755 if missing.
func Enroll(ctx context.Context, serverURL, token, dataDir, signingKeyPath, nebulaConfigPath string) error {
	if nebulaConfigPath == "" {
		nebulaConfigPath = filepath.Join(dataDir, "config.yml")
	}
	profile := models.AgentProfile{
		NebulaConfigPath: nebulaConfigPath,
		NebulaCAPath:     filepath.Join(dataDir, "ca.crt"),
		NebulaCertPath:   filepath.Join(dataDir, "host.crt"),
		NebulaKeyPath:    filepath.Join(dataDir, "host.key"),
		ConfigAckV1:      true,
	}
	return enrollWithProfile(ctx, serverURL, token, dataDir, signingKeyPath, profile, nil)
}

func enrollWithProfile(
	ctx context.Context,
	serverURL, token, dataDir, signingKeyPath string,
	profile models.AgentProfile,
	reload func() error,
) error {
	if dataDir == "" {
		return fmt.Errorf("dataDir is required")
	}
	if signingKeyPath == "" {
		return fmt.Errorf("signingKeyPath is required")
	}
	if err := profile.Validate(); err != nil {
		return err
	}
	// Pre-flight: verify every target directory is writable BEFORE the POST
	// so a permission error does not burn the single-use enrollment token.
	if err := preflightEnrollmentTargets(dataDir, signingKeyPath, profile); err != nil {
		return err
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
	reqBody, err := json.Marshal(struct {
		Token         string              `json:"token"`
		PublicKeyPEM  string              `json:"public_key_pem"`
		SigningPubPEM string              `json:"signing_public_key_pem"`
		Profile       models.AgentProfile `json:"profile"`
	}{
		Token: token, PublicKeyPEM: string(pubKeyPEM), SigningPubPEM: string(signingPubPEM), Profile: profile,
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
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		if readErr != nil {
			return fmt.Errorf("enrollment failed (HTTP %d, body unreadable: %w)", resp.StatusCode, readErr)
		}
		if len(body) > 512 {
			body = body[:512]
		}
		return fmt.Errorf("enrollment failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var enrollResp EnrollResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&enrollResp); err != nil {
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
	if err := fsutil.AtomicWriteFile(profile.NebulaKeyPath, secrets.privKeyPEM, 0o600); err != nil {
		return fmt.Errorf("write host key: %w", err)
	}

	// Save signing private key (ADR 0004 — used to sign poll requests).
	// Lives in its own directory, not dataDir; create parent if missing.
	if err := os.MkdirAll(filepath.Dir(signingKeyPath), 0o750); err != nil {
		return fmt.Errorf("create signing key dir: %w", err)
	}
	secrets.signingPrivPEM = pem.EncodeToMemory(&pem.Block{Type: SigningPrivateKeyPEMType, Bytes: secrets.signingPriv})
	if err := fsutil.AtomicWriteFile(signingKeyPath, secrets.signingPrivPEM, 0o600); err != nil {
		return fmt.Errorf("write signing key: %w", err)
	}

	// Validate the host certificate before writing: must be a valid
	// non-CA Curve25519 certificate with no trailing PEM blocks.
	hostCert, remainder, err := cert.UnmarshalCertificateFromPEM([]byte(enrollResp.CertificatePEM))
	if err != nil || strings.TrimSpace(string(remainder)) != "" || hostCert.IsCA() ||
		hostCert.Curve() != cert.Curve_CURVE25519 {
		return fmt.Errorf("enrollment response contains an invalid host certificate")
	}
	if err := fsutil.AtomicWriteFile(profile.NebulaCertPath, []byte(enrollResp.CertificatePEM), 0o644); err != nil {
		return fmt.Errorf("write host cert: %w", err)
	}

	// Validate the CA certificate: must be a valid CA with Curve25519
	// and not expired.
	caCert, caRemainder, err := cert.UnmarshalCertificateFromPEM([]byte(enrollResp.CACertificatePEM))
	if err != nil || strings.TrimSpace(string(caRemainder)) != "" || !caCert.IsCA() ||
		caCert.Curve() != cert.Curve_CURVE25519 || caCert.Expired(time.Now()) {
		return fmt.Errorf("enrollment response contains an invalid CA certificate")
	}
	if err := fsutil.AtomicWriteFile(profile.NebulaCAPath, []byte(enrollResp.CACertificatePEM), 0o644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	// Save config. 0o640 — rendered Nebula daemon config (host name,
	// nebula IPs, lighthouse list, firewall rules, paths to key/cert
	// files). No secrets in the file itself; the actual private key
	// lives in host.key, written above at 0o600.
	if err := fsutil.AtomicWriteFile(profile.NebulaConfigPath, []byte(enrollResp.ConfigYAML), 0o640); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if reload != nil {
		if err := reload(); err != nil {
			return fmt.Errorf("reload nebula after re-enrollment: %w", err)
		}
	}
	if enrollResp.ConfigVersion > 0 {
		hostCertificate, remainder, err := cert.UnmarshalCertificateFromPEM([]byte(enrollResp.CertificatePEM))
		if err != nil || len(bytes.TrimSpace(remainder)) != 0 {
			return fmt.Errorf("parse enrolled certificate for config ack")
		}
		fingerprint, err := hostCertificate.Fingerprint()
		if err != nil {
			return fmt.Errorf("fingerprint enrolled certificate for config ack: %w", err)
		}
		poller, err := NewPoller(PollerConfig{
			ServerURL: serverURL, Fingerprint: fingerprint, DataDir: dataDir,
			SigningKeyPath: signingKeyPath, NebulaConfigPath: profile.NebulaConfigPath,
			NebulaCAPath: profile.NebulaCAPath, NebulaCertPath: profile.NebulaCertPath,
			NebulaKeyPath: profile.NebulaKeyPath,
		}, slog.Default())
		if err != nil {
			slog.Warn("initial config ack skipped", "error", err)
		} else if err := poller.acknowledgeConfig(ctx, enrollResp.ConfigVersion); err != nil {
			// Enrollment files are already durable. The server keeps the version
			// pending and the first ordinary poll will redeliver it.
			slog.Warn("initial config ack failed; server will redeliver", "error", err)
		}
	}

	return nil
}

func preflightEnrollmentTargets(dataDir, signingKeyPath string, profile models.AgentProfile) error {
	targets := []struct {
		name string
		dir  string
	}{
		{name: "data dir", dir: dataDir},
		{name: "signing key dir", dir: filepath.Dir(signingKeyPath)},
		{name: "nebula config dir", dir: filepath.Dir(profile.NebulaConfigPath)},
		{name: "nebula CA dir", dir: filepath.Dir(profile.NebulaCAPath)},
		{name: "nebula cert dir", dir: filepath.Dir(profile.NebulaCertPath)},
		{name: "nebula key dir", dir: filepath.Dir(profile.NebulaKeyPath)},
	}
	seen := make(map[string]struct{}, len(targets))
	for _, target := range targets {
		if _, ok := seen[target.dir]; ok {
			continue
		}
		seen[target.dir] = struct{}{}
		if err := preflightWritable(target.dir); err != nil {
			return fmt.Errorf("%s: %w", target.name, err)
		}
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
