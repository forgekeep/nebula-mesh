package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// NetworkCreate creates a network via the API.
func NetworkCreate(serverURL, apiKey, name, cidr string) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	// Convert single CIDR to the new cidrs array format
	cidrs := []string{cidr}
	if cidr == "" {
		cidrs = []string{}
	}

	body := map[string]any{
		"name":  name,
		"cidrs": cidrs,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, serverURL+"/api/v1/networks", bytes.NewReader(data))
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

	var result struct {
		ID    string   `json:"id"`
		Name  string   `json:"name"`
		CIDRs []string `json:"cidrs"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	fmt.Printf("Network created: %s (ID: %s, CIDRs: %s)\n", result.Name, result.ID, fmt.Sprint(result.CIDRs))
	return nil
}

// NetworkList lists networks via the API.
func NetworkList(serverURL, apiKey string) error {
	if err := validateServerURL(serverURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/api/v1/networks", http.NoBody)
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

	var networks []struct {
		ID    string   `json:"id"`
		Name  string   `json:"name"`
		CIDRs []string `json:"cidrs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&networks); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	if len(networks) == 0 {
		fmt.Println("No networks found.")
		return nil
	}

	fmt.Printf("%-36s  %-20s  %s\n", "ID", "NAME", "CIDRS")
	for _, n := range networks {
		cidrsStr := fmt.Sprint(n.CIDRs)
		fmt.Printf("%-36s  %-20s  %s\n", n.ID, n.Name, cidrsStr)
	}
	return nil
}
