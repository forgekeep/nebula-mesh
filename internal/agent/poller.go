package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentpop "github.com/juev/nebula-mesh/internal/agent/pop"
	corepop "github.com/juev/nebula-mesh/internal/pop"
)

// UpdatesResponse is the response from the agent updates endpoint.
type UpdatesResponse struct {
	HasUpdates      bool     `json:"has_updates"`
	CertificatePEM  *string  `json:"certificate_pem,omitempty"`
	CACertPEM       *string  `json:"ca_certificate_pem,omitempty"`
	ConfigYAML      *string  `json:"config_yaml,omitempty"`
	Blocklist       []string `json:"blocklist"`
	RekeyRequired   bool     `json:"rekey_required,omitempty"`
	EnrollmentToken string   `json:"enrollment_token,omitempty"`
}

// RekeyError is returned by Poller.poll when the server signals that the
// agent must regenerate its keypair (force-rotate with new_key=true,
// ADR 0004 §7.1). The token attached to the error is single-use and
// short-lived; the caller is expected to invoke agent.Reenroll with it.
type RekeyError struct {
	Token string
}

func (e *RekeyError) Error() string { return "agent rekey required" }

// IsRekey reports whether err carries a server rekey signal.
func IsRekey(err error) bool {
	var re *RekeyError
	return err != nil && errorsAsRekey(err, &re)
}

func errorsAsRekey(err error, target **RekeyError) bool {
	type unwrapper interface{ Unwrap() error }
	for cur := err; cur != nil; {
		if re, ok := cur.(*RekeyError); ok {
			*target = re
			return true
		}
		if u, ok := cur.(unwrapper); ok {
			cur = u.Unwrap()
			continue
		}
		break
	}
	return false
}

// RevocationError is returned by Poller.poll when the management server
// signals that the agent should stop polling — either 403 revoked (the host
// is blocked) or 410 gone (the host row has been deleted). Run() returns
// this error so callers can exit with status 0 and avoid systemd
// auto-restart loops.
type RevocationError struct {
	StatusCode int
	Reason     string
	Body       string
}

func (e *RevocationError) Error() string {
	return fmt.Sprintf("agent revoked by server (HTTP %d, reason=%s): %s", e.StatusCode, e.Reason, e.Body)
}

// IsRevoked reports whether err originates from a 403/410 server response.
func IsRevoked(err error) bool {
	var re *RevocationError
	return err != nil && errorsAs(err, &re)
}

func errorsAs(err error, target any) bool {
	type unwrapper interface{ Unwrap() error }
	for cur := err; cur != nil; {
		if ptr, ok := target.(**RevocationError); ok {
			if re, ok := cur.(*RevocationError); ok {
				*ptr = re
				return true
			}
		}
		if u, ok := cur.(unwrapper); ok {
			cur = u.Unwrap()
			continue
		}
		break
	}
	return false
}

// PollerConfig holds configuration for the Poller.
type PollerConfig struct {
	ServerURL      string
	Fingerprint    string
	DataDir        string
	SigningKeyPath string
	Interval       time.Duration
	PIDFile        string
}

// Poller periodically checks the management server for updates.
type Poller struct {
	config     PollerConfig
	logger     *slog.Logger
	signalFunc func() error // for testing: override SIGHUP sending
	signingKey ed25519.PrivateKey
}

// NewPoller creates a new Poller and loads the Ed25519 signing key needed to
// sign poll requests (ADR 0004 §7.1). If the key cannot be loaded the
// returned error is propagated to the caller; the agent must re-enroll
// before polling can resume.
func NewPoller(cfg PollerConfig, logger *slog.Logger) (*Poller, error) {
	if cfg.SigningKeyPath == "" {
		return nil, fmt.Errorf("PollerConfig.SigningKeyPath is required")
	}
	priv, err := loadSigningKey(cfg.SigningKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	p := &Poller{
		config:     cfg,
		logger:     logger,
		signingKey: priv,
	}
	p.signalFunc = func() error {
		return signalNebulaFromPID(cfg.PIDFile)
	}
	return p, nil
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != SigningPrivateKeyPEMType {
		return nil, fmt.Errorf("signing key PEM at %s has wrong block type", path)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key has length %d, want %d", len(block.Bytes), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

// Run starts the poll loop, blocking until ctx is cancelled.
func (p *Poller) Run(ctx context.Context) error {
	p.logger.Info("starting poll loop", "interval", p.config.Interval, "server", p.config.ServerURL)

	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("poll loop stopped")
			return ctx.Err()
		case <-ticker.C:
			if err := p.poll(ctx); err != nil {
				if IsRevoked(err) {
					p.logger.Error("poll loop stopped by server revocation signal", "error", err)
					return err
				}
				if IsRekey(err) {
					p.logger.Info("server requested rekey; stopping poll loop so caller can re-enroll")
					return err
				}
				p.logger.Error("poll failed", "error", err)
			}
		}
	}
}

// PollOnce performs a single signed poll iteration and returns. The enroll
// subcommand uses it to verify the freshly enrolled host can reach the
// server before exiting. Errors are informational — callers decide whether
// to gate behaviour on them; the daemon's Run() never invokes PollOnce.
func (p *Poller) PollOnce(ctx context.Context) error {
	return p.poll(ctx)
}

func (p *Poller) poll(ctx context.Context) error {
	u := p.config.ServerURL + "/api/v1/agent/updates"
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return fmt.Errorf("create poll request: %w", err)
	}
	if err := p.signRequest(req); err != nil {
		return fmt.Errorf("sign poll request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("poll request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error("close response body", "error", err)
		}
	}()

	if resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusGone {
		body, _ := io.ReadAll(resp.Body)
		reason := "revoked"
		if resp.StatusCode == http.StatusGone {
			reason = "gone"
		}
		return &RevocationError{StatusCode: resp.StatusCode, Reason: reason, Body: string(body)}
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("poll failed (HTTP %d, body unreadable: %w)", resp.StatusCode, readErr)
		}
		return fmt.Errorf("poll failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var updates UpdatesResponse
	if err := json.NewDecoder(resp.Body).Decode(&updates); err != nil {
		return fmt.Errorf("decode updates: %w", err)
	}

	// Server-driven rekey takes precedence over routine updates. The
	// caller stops the loop, runs Reenroll(token), and restarts the
	// poller against the freshly enrolled keypair.
	if updates.RekeyRequired {
		if updates.EnrollmentToken == "" {
			return fmt.Errorf("server set rekey_required but no enrollment_token returned")
		}
		return &RekeyError{Token: updates.EnrollmentToken}
	}

	if !updates.HasUpdates {
		return nil
	}

	needsReload := false

	if updates.CertificatePEM != nil {
		if err := atomicWriteFile(filepath.Join(p.config.DataDir, "host.crt"), []byte(*updates.CertificatePEM), 0o644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		p.logger.Info("certificate updated")
		needsReload = true
	}

	if updates.CACertPEM != nil {
		if err := atomicWriteFile(filepath.Join(p.config.DataDir, "ca.crt"), []byte(*updates.CACertPEM), 0o644); err != nil {
			return fmt.Errorf("write CA cert: %w", err)
		}
		p.logger.Info("CA certificate updated")
		needsReload = true
	}

	if updates.ConfigYAML != nil {
		if err := atomicWriteFile(filepath.Join(p.config.DataDir, "config.yml"), []byte(*updates.ConfigYAML), 0o644); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
		p.logger.Info("config updated")
		needsReload = true
	}

	if needsReload {
		if err := p.signalFunc(); err != nil {
			p.logger.Warn("failed to signal nebula", "error", err)
		} else {
			p.logger.Info("nebula reloaded")
		}
	}

	return nil
}

// signRequest attaches the four ADR 0004 PoP headers to req: fingerprint,
// timestamp, nonce, signature over the canonical string.
func (p *Poller) signRequest(req *http.Request) error {
	ts := time.Now().UTC().Format(time.RFC3339)
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return fmt.Errorf("read nonce bytes: %w", err)
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)

	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	canonical := corepop.CanonicalString(req.Method, req.URL.Path, host, ts, nonce)
	sig, err := agentpop.Sign(p.signingKey, canonical)
	if err != nil {
		return fmt.Errorf("sign canonical: %w", err)
	}
	req.Header.Set(corepop.HeaderFingerprint, p.config.Fingerprint)
	req.Header.Set(corepop.HeaderTimestamp, ts)
	req.Header.Set(corepop.HeaderNonce, nonce)
	req.Header.Set(corepop.HeaderSignature, agentpop.EncodeSignature(sig))
	return nil
}

// atomicWriteFile writes data to a temp file, syncs it, then renames to the target path.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// cleanup removes temp file on failure; set to nil after successful rename
	cleanup := func() {
		if removeErr := os.Remove(tmpPath); removeErr != nil && !os.IsNotExist(removeErr) {
			slog.Error("remove temp file", "path", tmpPath, "error", removeErr)
		}
	}

	if _, err := tmp.Write(data); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			slog.Error("close temp file after write error", "path", tmpPath, "error", closeErr)
		}
		cleanup()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		if closeErr := tmp.Close(); closeErr != nil {
			slog.Error("close temp file after sync error", "path", tmpPath, "error", closeErr)
		}
		cleanup()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		cleanup()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename temp to target: %w", err)
	}
	return nil
}

// signalNebulaFromPID reads the PID from file and sends SIGHUP to the nebula process.
func signalNebulaFromPID(pidFile string) error {
	if pidFile == "" {
		return fmt.Errorf("nebula PID file not configured")
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("read PID file %s: %w", pidFile, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("parse PID from %s: %w", pidFile, err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}

	return proc.Signal(syscall.SIGHUP)
}
