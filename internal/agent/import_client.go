package agent

import (
	"bytes"
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
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/fsutil"
	"github.com/forgekeep/nebula-mesh/internal/importproof"
)

type ImportResult struct {
	HostID      string `json:"host_id"`
	Fingerprint string `json:"certificate_fingerprint"`
	Status      string `json:"status"`
	Created     bool   `json:"created"`
	SessionID   string `json:"-"`
}

type importHTTPError struct {
	Status int
	Body   string
}

func (e *importHTTPError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Body) }

type importChallengeResponse struct {
	ChallengeID     string    `json:"challenge_id"`
	SessionID       string    `json:"session_id"`
	ServerPublicKey string    `json:"server_public_key"`
	ServerNonce     string    `json:"server_nonce"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// ImportExisting registers a discovered installation without writing any
// Nebula-owned file. It creates or reuses only the agent Ed25519 signing key.
func ImportExisting(
	ctx context.Context,
	serverURL, token, signingKeyPath string,
	discovery *ExistingDiscovery,
) (*ImportResult, error) {
	if discovery == nil || discovery.State != DiscoveryComplete {
		return nil, errors.New("complete existing Nebula discovery is required")
	}
	if signingKeyPath == "" {
		return nil, errors.New("signing key path is required")
	}
	defer discovery.Wipe()

	signingPrivate, err := loadOrCreateSigningKey(signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("prepare agent signing key: %w", err)
	}
	defer clear(signingPrivate)
	signingPublic := signingPrivate.Public().(ed25519.PublicKey)
	signingPublicPEM := string(pem.EncodeToMemory(&pem.Block{Type: SigningPublicKeyPEMType, Bytes: signingPublic}))
	payload := map[string]any{
		"token": token, "ca_certificate_pem": discovery.CACertificatePEM,
		"agent_signing_public_key_pem": signingPublicPEM,
		"payload_hash":                 discovery.PayloadHash, "snapshot": discovery.Snapshot,
	}
	client := &http.Client{
		Timeout: defaultAgentHTTPTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var challenge importChallengeResponse
	if err := postImportJSON(ctx, client, serverURL+"/api/v1/agent/import/challenge", payload, http.StatusCreated, &challenge); err != nil {
		return nil, fmt.Errorf("create import challenge: %w", err)
	}
	if challenge.ChallengeID == "" || challenge.SessionID == "" || challenge.ServerPublicKey == "" || challenge.ServerNonce == "" {
		return nil, errors.New("create import challenge: incomplete server response")
	}
	serverPublicKey, err := base64.RawURLEncoding.DecodeString(challenge.ServerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode import challenge public key: %w", err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.ServerNonce)
	if err != nil {
		return nil, fmt.Errorf("decode import challenge nonce: %w", err)
	}
	hostCertificate, _, err := cert.UnmarshalCertificateFromPEM([]byte(discovery.Snapshot.CertificatePEM))
	if err != nil {
		return nil, fmt.Errorf("parse discovered host certificate: %w", err)
	}
	fingerprint, err := hostCertificate.Fingerprint()
	if err != nil {
		return nil, fmt.Errorf("fingerprint discovered host certificate: %w", err)
	}
	proof, err := importproof.Compute(discovery.HostPrivateKey, serverPublicKey, nonce, importproof.Binding{
		SessionID: challenge.SessionID, CertificateFingerprint: fingerprint,
		AgentSigningPublicKeyPEM: signingPublicPEM, PayloadHash: discovery.PayloadHash,
	})
	if err != nil {
		return nil, fmt.Errorf("compute import proof: %w", err)
	}
	defer clear(proof)
	payload["challenge_id"] = challenge.ChallengeID
	payload["proof"] = base64.RawURLEncoding.EncodeToString(proof)
	finalPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal final import request: %w", err)
	}
	var result ImportResult
	initialErr := postImportBytes(ctx, client, serverURL+"/api/v1/agent/import", finalPayload, 0, &result)
	if initialErr != nil {
		var responseError *importHTTPError
		if errors.As(initialErr, &responseError) {
			return nil, fmt.Errorf("register existing host: %w", initialErr)
		}
		if !challenge.ExpiresAt.IsZero() && !time.Now().Before(challenge.ExpiresAt) {
			return nil, fmt.Errorf("register existing host: %w; import challenge expired before retry", initialErr)
		}
		retryErr := postImportBytes(ctx, client, serverURL+"/api/v1/agent/import", finalPayload, 0, &result)
		if retryErr != nil {
			if isImportChallengeUsed(retryErr) {
				confirmErr := confirmImportedRegistration(ctx, serverURL, signingKeyPath, fingerprint, discovery)
				if confirmErr == nil {
					return recoveredImportResult(fingerprint, challenge.SessionID), nil
				}
				return nil, fmt.Errorf("register existing host: %w; confirmation poll: %w", initialErr, confirmErr)
			}
			return nil, fmt.Errorf("register existing host: %w; retry: %w", initialErr, retryErr)
		}
	}
	if result.HostID == "" || result.Fingerprint == "" || result.Status == "" {
		return nil, errors.New("register existing host: incomplete server response")
	}
	result.SessionID = challenge.SessionID
	return &result, nil
}

func recoveredImportResult(fingerprint, sessionID string) *ImportResult {
	return &ImportResult{Fingerprint: fingerprint, Status: "importing", Created: false, SessionID: sessionID}
}

func confirmImportedRegistration(
	ctx context.Context,
	serverURL, signingKeyPath, fingerprint string,
	discovery *ExistingDiscovery,
) error {
	poller, err := NewPoller(PollerConfig{
		ServerURL: serverURL, Fingerprint: fingerprint,
		DataDir:        filepath.Dir(discovery.Snapshot.Profile.NebulaCertPath),
		SigningKeyPath: signingKeyPath, Interval: time.Second,
		NebulaConfigPath: discovery.Snapshot.Profile.NebulaConfigPath,
		NebulaCAPath:     discovery.Snapshot.Profile.NebulaCAPath,
		NebulaCertPath:   discovery.Snapshot.Profile.NebulaCertPath,
		NebulaKeyPath:    discovery.Snapshot.Profile.NebulaKeyPath,
		ImportSessionID:  "",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		return err
	}
	return poller.PollOnce(ctx)
}

func postImportJSON(ctx context.Context, client *http.Client, url string, body any, wantStatus int, output any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	return postImportBytes(ctx, client, url, encoded, wantStatus, output)
}

func postImportBytes(ctx context.Context, client *http.Client, url string, encoded []byte, wantStatus int, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer response.Body.Close()
	accepted := response.StatusCode == wantStatus
	if wantStatus == 0 {
		accepted = response.StatusCode == http.StatusOK || response.StatusCode == http.StatusCreated
	}
	if !accepted {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		return &importHTTPError{Status: response.StatusCode, Body: string(message)}
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func isImportChallengeUsed(err error) bool {
	var responseError *importHTTPError
	if !errors.As(err, &responseError) || responseError.Status != http.StatusConflict {
		return false
	}
	var body struct {
		Error string `json:"error"`
	}
	return json.Unmarshal([]byte(responseError.Body), &body) == nil && body.Error == "import_challenge_used"
}

func loadOrCreateSigningKey(path string) (ed25519.PrivateKey, error) {
	privateKey, err := loadSigningKey(path)
	if err == nil {
		return privateKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create signing key directory: %w", err)
	}
	_, generated, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: SigningPrivateKeyPEMType, Bytes: generated})
	file, err := os.CreateTemp(filepath.Dir(path), ".host.signing.key-")
	if err != nil {
		clear(generated)
		clear(encoded)
		return nil, err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		clear(generated)
		clear(encoded)
		return nil, err
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		clear(generated)
		clear(encoded)
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		clear(generated)
		clear(encoded)
		return nil, err
	}
	if err := file.Close(); err != nil {
		clear(generated)
		clear(encoded)
		return nil, err
	}
	if err := os.Link(temporaryPath, path); errors.Is(err, os.ErrExist) {
		clear(generated)
		clear(encoded)
		return loadSigningKey(path)
	} else if err != nil {
		clear(generated)
		clear(encoded)
		return nil, err
	}
	// fsync the directory so the hard link survives a crash. Best-effort and
	// non-fatal: the link already landed, and on Windows directory fsync is not
	// supported (see fsutil.SyncDir).
	fsutil.SyncDir(filepath.Dir(path))
	clear(encoded)
	return generated, nil
}
