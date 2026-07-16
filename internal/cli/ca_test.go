package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/slackhq/nebula/cert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/pki"
)

func TestCARotate_BuildsCorrectRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/cas/ca-123/rotate", r.URL.Path)

		// Verify Bearer auth header
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-key", authHeader)

		// Return mock response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"id":             "new-ca-id",
			"name":           "ca-name-rotated",
			"predecessor_id": "ca-123",
			"fingerprint":    "abc123def456",
			"status":         "active",
		})
	}))
	defer server.Close()

	// Capture stdout
	rOut, wOut, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = wOut

	err := CARotate(server.URL, "test-key", "ca-123")

	wOut.Close()
	os.Stdout = oldStdout
	output, _ := io.ReadAll(rOut)

	require.NoError(t, err)
	assert.Contains(t, string(output), "Rotated CA: new-ca-id")
}

func TestCARotate_EmptyAPIKey(t *testing.T) {
	err := CARotate("http://localhost:8080", "", "ca-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api-key is required")
}

func TestCAImport_RejectsInsecureNonLoopbackBeforeReadingFiles(t *testing.T) {
	for _, serverURL := range []string{
		"http://mesh.example.com:8080",
		"http://localhost:8080",
		"http://10.0.0.5:8080",
	} {
		err := CAImport(serverURL, "api-key", "existing", "/missing/ca.crt", "/missing/ca.key", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTPS or literal-loopback HTTP")
		assert.NotContains(t, err.Error(), "read CA certificate")
	}
}

func TestValidateSecretImportServerURL(t *testing.T) {
	for _, serverURL := range []string{"https://mesh.example.com", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		require.NoError(t, validateSecretImportServerURL(serverURL))
	}
	for _, serverURL := range []string{"http://localhost:8080", "http://10.0.0.5:8080", "http://mesh.example.com"} {
		require.Error(t, validateSecretImportServerURL(serverURL))
	}
}

func TestCAImport_DoesNotFollowRedirects(t *testing.T) {
	dir := t.TempDir()
	manager, err := pki.NewCA("existing", time.Hour)
	require.NoError(t, err)
	defer manager.Wipe()
	certificatePEM, err := manager.CACertPEM()
	require.NoError(t, err)
	keyPEM := cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, manager.RawKey())
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	require.NoError(t, os.WriteFile(certPath, certificatePEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls++ }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	previousClient := httpClient
	httpClient = source.Client()
	t.Cleanup(func() { httpClient = previousClient })

	err = CAImport(source.URL, "api-key", "existing", certPath, keyPath, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 307")
	require.Zero(t, targetCalls)
}

func TestCAImport_DecryptsEncryptedKeyLocally(t *testing.T) {
	dir := t.TempDir()
	manager, err := pki.NewCA("existing", time.Hour)
	require.NoError(t, err)
	defer manager.Wipe()
	certificatePEM, err := manager.CACertPEM()
	require.NoError(t, err)
	passphrase := []byte("correct horse battery staple")
	encryptedKeyPEM, err := cert.EncryptAndMarshalSigningPrivateKey(
		cert.Curve_CURVE25519,
		manager.RawKey(),
		passphrase,
		cert.NewArgon2Parameters(64, 1, 1),
	)
	require.NoError(t, err)
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	passphrasePath := filepath.Join(dir, "passphrase")
	require.NoError(t, os.WriteFile(certPath, certificatePEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, encryptedKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(passphrasePath, append(append([]byte(nil), passphrase...), '\n'), 0o600))

	var receivedName string
	var receivedCertificate, receivedPrivateKey, receivedPassphrase []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/cas/import", r.URL.Path)
		require.Equal(t, "Bearer api-key", r.Header.Get("Authorization"))
		reader, err := r.MultipartReader()
		require.NoError(t, err)
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)
			value, err := io.ReadAll(part)
			require.NoError(t, err)
			switch part.FormName() {
			case "name":
				receivedName = string(value)
			case "certificate":
				receivedCertificate = value
			case "private_key":
				receivedPrivateKey = value
			case "passphrase":
				receivedPassphrase = value
			}
		}
		_, _, curve, parseErr := cert.UnmarshalSigningPrivateKeyFromPEM(receivedPrivateKey)
		require.NoError(t, parseErr)
		require.Equal(t, cert.Curve_CURVE25519, curve)
		require.Empty(t, receivedPassphrase)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		require.NoError(t, json.NewEncoder(w).Encode(caInfo{ID: "ca-id", Name: "existing", Fingerprint: "fp", Status: "active"}))
	}))
	defer server.Close()
	previousClient := httpClient
	httpClient = server.Client()
	t.Cleanup(func() { httpClient = previousClient })

	output := captureCLIStdout(t, func() error {
		return CAImport(server.URL, "api-key", "existing", certPath, keyPath, passphrasePath)
	})
	require.Equal(t, "existing", receivedName)
	require.Equal(t, certificatePEM, receivedCertificate)
	require.Equal(t, 1, strings.Count(output, "ca-id"))
	require.Equal(t, 1, strings.Count(output, "fp"))
}

func TestCAImport_WrongPassphraseDoesNotSendRequest(t *testing.T) {
	dir := t.TempDir()
	manager, err := pki.NewCA("existing", time.Hour)
	require.NoError(t, err)
	defer manager.Wipe()
	certificatePEM, err := manager.CACertPEM()
	require.NoError(t, err)
	encryptedKeyPEM, err := cert.EncryptAndMarshalSigningPrivateKey(
		cert.Curve_CURVE25519,
		manager.RawKey(),
		[]byte("correct"),
		cert.NewArgon2Parameters(64, 1, 1),
	)
	require.NoError(t, err)
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	passphrasePath := filepath.Join(dir, "passphrase")
	require.NoError(t, os.WriteFile(certPath, certificatePEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, encryptedKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(passphrasePath, []byte("wrong\n"), 0o600))

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requestCount++ }))
	defer server.Close()
	previousClient := httpClient
	httpClient = server.Client()
	t.Cleanup(func() { httpClient = previousClient })

	err = CAImport(server.URL, "api-key", "existing", certPath, keyPath, passphrasePath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt CA private key")
	require.Zero(t, requestCount)
}

func captureCLIStdout(t *testing.T, fn func() error) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	require.NoError(t, err)
	previousStdout := os.Stdout
	os.Stdout = writer
	callErr := fn()
	require.NoError(t, writer.Close())
	os.Stdout = previousStdout
	output, readErr := io.ReadAll(reader)
	require.NoError(t, readErr)
	require.NoError(t, reader.Close())
	require.NoError(t, callErr)
	return string(bytes.TrimSpace(output))
}
