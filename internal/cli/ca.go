package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"github.com/slackhq/nebula/cert"

	"github.com/forgekeep/nebula-mesh/internal/keystore"
)

type caCreateRequest struct {
	Name     string `json:"name"`
	Duration string `json:"duration,omitempty"`
}

type importCARequest struct {
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate_pem"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	Passphrase     string `json:"passphrase,omitempty"`
}

type caInfo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	OwnerOperatorID string `json:"owner_operator_id"`
	Fingerprint     string `json:"fingerprint"`
	Status          string `json:"status"`
	IsDefault       bool   `json:"is_default"`
}

type caRotateResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	PredecessorID string `json:"predecessor_id"`
	Fingerprint   string `json:"fingerprint"`
	Status        string `json:"status"`
}

// CACreate creates a new CA via the API.
func CACreate(serverURL, apiKey, name, duration string) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("--name is required")
	}
	body, err := json.Marshal(caCreateRequest{Name: name, Duration: duration})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, serverURL+"/api/v1/cas", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("close response body", "error", err)
		}
	}()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	var out caInfo
	if err := json.Unmarshal(respBody, &out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("CA created: %s (ID: %s)\n", out.Name, out.ID)
	fmt.Printf("Fingerprint: %s\n", out.Fingerprint)
	return nil
}

// CAImport imports an existing Nebula CA. Encrypted keys are decrypted
// locally using passphraseFile; the server receives neither the passphrase nor
// the encrypted high-cost KDF payload.
func CAImport(serverURL, apiKey, name, certFile, keyFile, passphraseFile string) error {
	if err := validateSecretImportServerURL(serverURL); err != nil {
		return err
	}
	if apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}
	if strings.TrimSpace(name) == "" || certFile == "" || keyFile == "" {
		return fmt.Errorf("--name, --cert-file, and --key-file are required")
	}

	certificatePEM, err := readBoundedImportFile(certFile, 1<<20)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	privateKeyPEM, err := readBoundedImportFile(keyFile, 1<<20)
	if err != nil {
		return fmt.Errorf("read CA private key: %w", err)
	}
	defer keystore.Zeroize(privateKeyPEM)

	uploadKeyPEM := privateKeyPEM
	rawKey, remainder, _, parseErr := cert.UnmarshalSigningPrivateKeyFromPEM(privateKeyPEM)
	if errors.Is(parseErr, cert.ErrPrivateKeyEncrypted) {
		if passphraseFile == "" {
			return fmt.Errorf("--passphrase-file is required for an encrypted CA private key")
		}
		passphraseBuffer, err := readBoundedImportFile(passphraseFile, 64<<10)
		if err != nil {
			return fmt.Errorf("read CA key passphrase: %w", err)
		}
		defer keystore.Zeroize(passphraseBuffer)
		passphrase := bytes.TrimRight(passphraseBuffer, "\r\n")
		decryptedCurve, decryptedKey, decryptedRemainder, err := cert.DecryptAndUnmarshalSigningPrivateKey(passphrase, privateKeyPEM)
		if err != nil {
			return fmt.Errorf("decrypt CA private key: %w", err)
		}
		rawKey, remainder = decryptedKey, decryptedRemainder
		defer keystore.Zeroize(rawKey)
		if len(bytes.TrimSpace(remainder)) != 0 {
			return fmt.Errorf("decrypt CA private key: unexpected trailing data")
		}
		uploadKeyPEM = cert.MarshalSigningPrivateKeyToPEM(decryptedCurve, rawKey)
		if uploadKeyPEM == nil {
			return fmt.Errorf("marshal decrypted CA private key: unsupported curve")
		}
		defer keystore.Zeroize(uploadKeyPEM)
	} else {
		if parseErr != nil {
			return fmt.Errorf("parse CA private key: %w", parseErr)
		}
		defer keystore.Zeroize(rawKey)
		if len(bytes.TrimSpace(remainder)) != 0 {
			return fmt.Errorf("parse CA private key: unexpected trailing data")
		}
	}

	body, err := json.Marshal(importCARequest{
		Name:           strings.TrimSpace(name),
		CertificatePEM: string(certificatePEM),
		PrivateKeyPEM:  string(uploadKeyPEM),
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	defer keystore.Zeroize(body)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, strings.TrimRight(serverURL, "/")+"/api/v1/cas/import", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := *httpClient
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("close response body", "error", err)
		}
	}()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed (HTTP %d): %s", resp.StatusCode, string(responseBody))
	}
	var imported caInfo
	if err := json.Unmarshal(responseBody, &imported); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("CA imported: %s (ID: %s)\n", imported.Name, imported.ID)
	fmt.Printf("Fingerprint: %s\n", imported.Fingerprint)
	return nil
}

func validateSecretImportServerURL(serverURL string) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	parsed, err := url.Parse(serverURL)
	if err != nil {
		return err
	}
	if parsed.Scheme == "https" {
		return nil
	}
	addr, err := netip.ParseAddr(parsed.Hostname())
	if err == nil && addr.Unmap().IsLoopback() {
		return nil
	}
	return fmt.Errorf("CA private key import requires HTTPS or literal-loopback HTTP; refusing %q", serverURL)
}

func readBoundedImportFile(path string, maxBytes int64) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- paths are explicit operator CLI arguments
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > maxBytes {
		keystore.Zeroize(data)
		return nil, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return data, nil
}

// CAList prints the CAs visible to the caller.
func CAList(serverURL, apiKey string) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/api/v1/cas", http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("close response body", "error", err)
		}
	}()
	var cas []caInfo
	if err := json.NewDecoder(resp.Body).Decode(&cas); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(cas) == 0 {
		fmt.Println("No CAs found.")
		return nil
	}
	fmt.Printf("%-36s  %-20s  %-10s  %-7s  %s\n", "ID", "NAME", "STATUS", "DEFAULT", "FINGERPRINT")
	for _, c := range cas {
		def := ""
		if c.IsDefault {
			def = "yes"
		}
		fmt.Printf("%-36s  %-20s  %-10s  %-7s  %s\n", c.ID, c.Name, c.Status, def, c.Fingerprint)
	}
	return nil
}

// CADelete deletes a CA by id. Fails if any network still references it.
func CADelete(serverURL, apiKey, id string) error {
	return doHostAction(serverURL, apiKey, "DELETE", "/api/v1/cas/"+id, http.StatusNoContent, "CA deleted")
}

// CARotate rotates a CA via the API.
func CARotate(serverURL, apiKey, id string) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	if apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, serverURL+"/api/v1/cas/"+id+"/rotate", http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("close response body", "error", err)
		}
	}()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	var out caRotateResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("Rotated CA: %s (predecessor: %s, fingerprint: %s)\n", out.ID, out.PredecessorID, out.Fingerprint)
	return nil
}
