package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// HostCreate creates a host via the API.
func HostCreate(serverURL, apiKey, networkID, name, nebulaIP, role string, groups []string, publicIP string, listenPort int) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	// Convert single nebulaIP to the new nebula_ips array format
	nebullaIPs := []string{nebulaIP}
	if nebulaIP == "" {
		nebullaIPs = []string{}
	}

	body := map[string]any{
		"network_id": networkID,
		"name":       name,
		"nebula_ips": nebullaIPs,
		"role":       role,
		"groups":     groups,
	}
	if publicIP != "" {
		body["public_ip"] = publicIP
	}
	if listenPort > 0 {
		body["listen_port"] = listenPort
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, serverURL+"/api/v1/hosts", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
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

	var result struct {
		Host struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"host"`
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	fmt.Printf("Host created: %s (ID: %s)\n", result.Host.Name, result.Host.ID)
	fmt.Printf("Enrollment token: %s\n", result.EnrollmentToken)
	return nil
}

// HostDelete deletes a host via the API.
func HostDelete(serverURL, apiKey, hostID string) error {
	return doHostAction(serverURL, apiKey, "DELETE", "/api/v1/hosts/"+hostID, http.StatusNoContent, "deleted")
}

// HostBlock blocks a host via the API.
func HostBlock(serverURL, apiKey, hostID string) error {
	return doHostAction(serverURL, apiKey, "POST", "/api/v1/hosts/"+hostID+"/block", http.StatusOK, "blocked")
}

// HostUnblock unblocks a host via the API. The host is moved back to pending
// and must re-enroll to obtain a new certificate.
func HostUnblock(serverURL, apiKey, hostID string) error {
	return doHostAction(serverURL, apiKey, "POST", "/api/v1/hosts/"+hostID+"/unblock", http.StatusOK, "unblocked (re-enrollment required)")
}

func doHostAction(serverURL, apiKey, method, path string, wantStatus int, verb string) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	if apiKey == "" {
		return fmt.Errorf("--api-key is required")
	}
	if serverURL == "" {
		return fmt.Errorf("--server is required")
	}

	req, err := http.NewRequestWithContext(context.Background(), method, serverURL+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("close response body", "error", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	if resp.StatusCode != wantStatus {
		return fmt.Errorf("failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	fmt.Printf("Host %s.\n", verb)
	return nil
}

// HostList lists hosts via the API.
func HostList(serverURL, apiKey, networkID string) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	u := serverURL + "/api/v1/hosts"
	if networkID != "" {
		u += "?network_id=" + url.QueryEscape(networkID)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, u, http.NoBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			slog.Error("close response body", "error", err)
		}
	}()

	var hosts []struct {
		ID        string   `json:"id"`
		Name      string   `json:"name"`
		NebulaIPs []string `json:"nebula_ips"`
		Role      string   `json:"role"`
		Status    string   `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if len(hosts) == 0 {
		fmt.Println("No hosts found.")
		return nil
	}

	fmt.Printf("%-36s  %-20s  %-40s  %-12s  %s\n", "ID", "NAME", "NEBULA IPS", "ROLE", "STATUS")
	for _, h := range hosts {
		ipsStr := strings.Join(h.NebulaIPs, ", ")
		fmt.Printf("%-36s  %-20s  %-40s  %-12s  %s\n", h.ID, h.Name, ipsStr, h.Role, h.Status)
	}
	return nil
}
