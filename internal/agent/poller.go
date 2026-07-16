package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	nebulaconfig "github.com/slackhq/nebula/config"

	agentpop "github.com/forgekeep/nebula-mesh/internal/agent/pop"
	"github.com/forgekeep/nebula-mesh/internal/fsutil"
	corepop "github.com/forgekeep/nebula-mesh/internal/pop"
)

// UpdatesResponse is the response from the agent updates endpoint.
type UpdatesResponse struct {
	HasUpdates      bool     `json:"has_updates"`
	CertificatePEM  *string  `json:"certificate_pem,omitempty"`
	CACertPEM       *string  `json:"ca_certificate_pem,omitempty"`
	ConfigYAML      *string  `json:"config_yaml,omitempty"`
	ConfigVersion   int      `json:"config_version,omitempty"`
	Blocklist       []string `json:"blocklist"`
	ImportPending   bool     `json:"import_pending,omitempty"`
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
		re := &RekeyError{}
		if errors.As(cur, &re) {
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

// PollHTTPError preserves a non-terminal poll status so bootstrap recovery can
// distinguish an unknown signing identity (401) from transport ambiguity.
type PollHTTPError struct {
	StatusCode int
	Body       string
	ReadErr    error
}

func (e *PollHTTPError) Error() string {
	if e.ReadErr != nil {
		return fmt.Sprintf("poll failed (HTTP %d, body unreadable: %v)", e.StatusCode, e.ReadErr)
	}
	return fmt.Sprintf("poll failed (HTTP %d): %s", e.StatusCode, e.Body)
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
			re := &RevocationError{}
			if errors.As(cur, &re) {
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

// defaultAgentHTTPTimeout bounds a single outbound agent HTTP request (enroll
// or poll) so a connected-but-unresponsive server cannot stall the call
// indefinitely (#193). http.DefaultClient has no timeout, so it is never used
// for agent requests.
const defaultAgentHTTPTimeout = 30 * time.Second

// PollerConfig holds configuration for the Poller.
type PollerConfig struct {
	ServerURL      string
	Fingerprint    string
	DataDir        string
	SigningKeyPath string
	Interval       time.Duration
	PIDFile        string
	// NebulaConfigPath is where the rendered Nebula config.yml is written.
	// Empty falls back to DataDir/config.yml. Honors agent.yml's
	// nebula_config_path so the daemon writes the config to the file Nebula
	// actually reads, not always DataDir/config.yml (#224).
	NebulaConfigPath string
	NebulaCAPath     string
	NebulaCertPath   string
	NebulaKeyPath    string
	ImportSessionID  string
	// HTTPTimeout bounds a single poll request. Zero or negative falls back
	// to defaultAgentHTTPTimeout.
	HTTPTimeout time.Duration
}

// Poller periodically checks the management server for updates.
type Poller struct {
	config     PollerConfig
	logger     *slog.Logger
	signalFunc func() error // for testing: override SIGHUP sending
	signingKey ed25519.PrivateKey
	httpClient *http.Client
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
	timeout := cfg.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultAgentHTTPTimeout
	}
	p := &Poller{
		config:     cfg,
		logger:     logger,
		signingKey: priv,
		httpClient: &http.Client{Timeout: timeout},
	}
	p.signalFunc = func() error {
		return signalNebulaFromPID(cfg.PIDFile)
	}
	return p, nil
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-controlled signing-key path from agent config, documented API contract
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

// Run starts the poll loop, blocking until ctx is canceled.
func (p *Poller) Run(ctx context.Context) error {
	p.logger.Info("starting poll loop", "interval", p.config.Interval, "server", p.config.ServerURL)

	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	// Poll once immediately so a freshly (re)started agent — host reboot,
	// package upgrade, crash recovery — learns about pending cert rotations,
	// config changes, revocation, or rekey requests without waiting a full
	// interval (#228). The same terminal-signal policy as the ticker branch
	// applies, so a revoked/rekey host stops here too.
	if ctx.Err() == nil {
		if err := p.handlePollResult(p.poll(ctx)); err != nil {
			return err
		}
	}

	for {
		select {
		case <-ctx.Done():
			p.logger.Info("poll loop stopped")
			return ctx.Err()
		case <-ticker.C:
			if err := p.handlePollResult(p.poll(ctx)); err != nil {
				return err
			}
		}
	}
}

// handlePollResult applies the terminal-signal policy shared by the immediate
// startup poll and the ticker loop, so the two paths cannot drift. It returns a
// non-nil error only when the loop must stop: a server revocation (403/410) or
// a rekey request. Transient errors are logged and nil is returned so the
// caller keeps polling.
func (p *Poller) handlePollResult(err error) error {
	if err == nil {
		return nil
	}
	if IsRevoked(err) {
		p.logger.Error("poll loop stopped by server revocation signal", "error", err)
		return err
	}
	if IsRekey(err) {
		p.logger.Info("server requested rekey; stopping poll loop so caller can re-enroll")
		return err
	}
	p.logger.Error("poll failed", "error", err)
	return nil
}

// PollOnce performs a single signed poll iteration and returns. The enroll
// subcommand uses it to verify the freshly enrolled host can reach the
// server before exiting. Errors are informational — callers decide whether
// to gate behavior on them; the daemon's Run() never invokes PollOnce.
func (p *Poller) PollOnce(ctx context.Context) error {
	return p.poll(ctx)
}

func (p *Poller) poll(ctx context.Context) error {
	u := p.config.ServerURL + "/api/v1/agent/updates"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return fmt.Errorf("create poll request: %w", err)
	}
	if err := p.signRequest(req); err != nil {
		return fmt.Errorf("sign poll request: %w", err)
	}
	resp, err := p.httpClient.Do(req)
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
		var signal struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(body, &signal) == nil && signal.Reason != "" {
			reason = signal.Reason
		}
		return &RevocationError{StatusCode: resp.StatusCode, Reason: reason, Body: string(body)}
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(resp.Body)
		return &PollHTTPError{StatusCode: resp.StatusCode, Body: string(body), ReadErr: readErr}
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
	var renewedFingerprint string
	if updates.CertificatePEM != nil {
		certificate, remainder, err := cert.UnmarshalCertificateFromPEM([]byte(*updates.CertificatePEM))
		if err != nil || strings.TrimSpace(string(remainder)) != "" || certificate.IsCA() {
			return fmt.Errorf("validate returned certificate: invalid host certificate")
		}
		renewedFingerprint, err = certificate.Fingerprint()
		if err != nil {
			return fmt.Errorf("fingerprint returned certificate: %w", err)
		}
	}
	if updates.ConfigYAML != nil {
		if err := p.validateCandidateConfig(*updates.ConfigYAML); err != nil {
			return err
		}
		if err := p.ensureImportBackup(); err != nil {
			return err
		}
	}

	if updates.CertificatePEM != nil {
		if err := fsutil.AtomicWriteFile(p.nebulaCertPath(), []byte(*updates.CertificatePEM), 0o644); err != nil {
			return fmt.Errorf("write cert: %w", err)
		}
		p.config.Fingerprint = renewedFingerprint
		p.logger.Info("certificate updated")
		needsReload = true
	}

	if updates.CACertPEM != nil {
		if err := fsutil.AtomicWriteFile(p.nebulaCAPath(), []byte(*updates.CACertPEM), 0o644); err != nil {
			return fmt.Errorf("write CA cert: %w", err)
		}
		p.logger.Info("CA certificate updated")
		needsReload = true
	}

	if updates.ConfigYAML != nil {
		if err := fsutil.AtomicWriteFile(p.nebulaConfigPath(), []byte(*updates.ConfigYAML), 0o644); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
		p.logger.Info("config updated", "path", p.nebulaConfigPath())
		needsReload = true
	}

	reloadDelivered := true
	if needsReload {
		if err := p.signalFunc(); err != nil {
			p.logger.Warn("failed to signal nebula", "error", err)
			if p.config.PIDFile != "" {
				reloadDelivered = false
			}
		} else {
			p.logger.Info("nebula reloaded")
		}
	}
	if updates.ConfigYAML != nil && updates.ConfigVersion > 0 && reloadDelivered {
		if err := p.acknowledgeConfig(ctx, updates.ConfigVersion); err != nil {
			return fmt.Errorf("acknowledge config version %d: %w", updates.ConfigVersion, err)
		}
	}

	return nil
}

func (p *Poller) acknowledgeConfig(ctx context.Context, version int) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/api/v1/agent/config-ack/%d", p.config.ServerURL, version), http.NoBody)
	if err != nil {
		return fmt.Errorf("create config ack request: %w", err)
	}
	if err := p.signRequest(request); err != nil {
		return fmt.Errorf("sign config ack request: %w", err)
	}
	response, err := p.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("config ack request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return fmt.Errorf("config ack failed (HTTP %d): %s", response.StatusCode, body)
	}
	return nil
}

func (p *Poller) validateCandidateConfig(raw string) error {
	directory := filepath.Dir(p.nebulaConfigPath())
	file, err := os.CreateTemp(directory, ".nebula-agent-candidate-")
	if err != nil {
		return fmt.Errorf("create candidate config: %w", err)
	}
	path := file.Name()
	defer os.Remove(path)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure candidate config: %w", err)
	}
	if _, err := file.WriteString(raw); err != nil {
		_ = file.Close()
		return fmt.Errorf("write candidate config: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync candidate config: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close candidate config: %w", err)
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	configuration := nebulaconfig.NewC(logger)
	if err := configuration.Load(path); err != nil {
		return fmt.Errorf("validate candidate config: %w", err)
	}
	expected := map[string]string{
		"pki.ca": p.nebulaCAPath(), "pki.cert": p.nebulaCertPath(), "pki.key": p.nebulaKeyPath(),
	}
	for key, want := range expected {
		if got := configuration.GetString(key, ""); got != want {
			return fmt.Errorf("validate candidate config: %s path %q does not match configured path %q", key, got, want)
		}
	}
	return nil
}

func (p *Poller) ensureImportBackup() error {
	if p.config.ImportSessionID == "" {
		return nil
	}
	if p.config.ImportSessionID == "." || p.config.ImportSessionID == ".." ||
		strings.ContainsAny(p.config.ImportSessionID, `/\\`) {
		return fmt.Errorf("invalid import session id for backup")
	}
	sourcePath := p.nebulaConfigPath()
	backupPath := sourcePath + ".pre-nebula-mesh." + p.config.ImportSessionID
	if info, err := os.Lstat(backupPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return fmt.Errorf("import backup destination must be a regular owner-only file: %s", backupPath)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect import backup: %w", err)
	}
	sourceInfo, err := os.Lstat(sourcePath)
	if err != nil {
		return fmt.Errorf("inspect source config for backup: %w", err)
	}
	if !sourceInfo.Mode().IsRegular() {
		return fmt.Errorf("source config for backup is not a regular file: %s", sourcePath)
	}
	source, err := os.Open(sourcePath) // #nosec G304 -- validated operator-configured regular file
	if err != nil {
		return fmt.Errorf("open source config for backup: %w", err)
	}
	defer source.Close()
	backup, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- deterministic validated destination
	if err != nil {
		return fmt.Errorf("create import backup: %w", err)
	}
	complete := false
	defer func() {
		_ = backup.Close()
		if !complete {
			_ = os.Remove(backupPath)
		}
	}()
	if err := backup.Chmod(0o600); err != nil {
		return fmt.Errorf("secure import backup: %w", err)
	}
	if _, err := io.Copy(backup, source); err != nil {
		return fmt.Errorf("copy import backup: %w", err)
	}
	if err := backup.Sync(); err != nil {
		return fmt.Errorf("sync import backup: %w", err)
	}
	if err := backup.Close(); err != nil {
		return fmt.Errorf("close import backup: %w", err)
	}
	directory, err := os.Open(filepath.Dir(backupPath))
	if err != nil {
		return fmt.Errorf("open import backup directory: %w", err)
	}
	err = directory.Sync()
	_ = directory.Close()
	if err != nil {
		return fmt.Errorf("sync import backup directory: %w", err)
	}
	complete = true
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

// nebulaConfigPath resolves where the rendered Nebula config is written: the
// configured NebulaConfigPath, or DataDir/config.yml when unset. Mirrors the
// fallback Enroll applies so the daemon and the initial enroll write target the
// same file (#224).
func (p *Poller) nebulaConfigPath() string {
	if p.config.NebulaConfigPath != "" {
		return p.config.NebulaConfigPath
	}
	return filepath.Join(p.config.DataDir, "config.yml")
}

func (p *Poller) nebulaCAPath() string {
	if p.config.NebulaCAPath != "" {
		return p.config.NebulaCAPath
	}
	return filepath.Join(p.config.DataDir, "ca.crt")
}

func (p *Poller) nebulaCertPath() string {
	if p.config.NebulaCertPath != "" {
		return p.config.NebulaCertPath
	}
	return filepath.Join(p.config.DataDir, "host.crt")
}

func (p *Poller) nebulaKeyPath() string {
	if p.config.NebulaKeyPath != "" {
		return p.config.NebulaKeyPath
	}
	return filepath.Join(p.config.DataDir, "host.key")
}

// signalNebulaFromPID reads the PID from file and sends SIGHUP to the nebula process.
func signalNebulaFromPID(pidFile string) error {
	if pidFile == "" {
		return fmt.Errorf("nebula PID file not configured")
	}

	data, err := os.ReadFile(pidFile) // #nosec G304 -- operator-controlled PID file path from agent config, documented API contract
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
