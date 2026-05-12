package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

type caCreateRequest struct {
	Name     string `json:"name"`
	Duration string `json:"duration,omitempty"`
}

type caInfo struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	OwnerOperatorID string `json:"owner_operator_id"`
	Fingerprint     string `json:"fingerprint"`
	Status          string `json:"status"`
	IsDefault       bool   `json:"is_default"`
}

// CACreate creates a new CA via the API.
func CACreate(serverURL, apiKey, name, duration string) error {
	if name == "" {
		return fmt.Errorf("--name is required")
	}
	body, _ := json.Marshal(caCreateRequest{Name: name, Duration: duration})
	req, err := http.NewRequest("POST", serverURL+"/api/v1/cas", bytes.NewReader(body))
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
	respBody, _ := io.ReadAll(resp.Body)
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

// CAList prints the CAs visible to the caller.
func CAList(serverURL, apiKey string) error {
	req, err := http.NewRequest("GET", serverURL+"/api/v1/cas", nil)
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
