package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// NetworkCreate creates a network via the API.
func NetworkCreate(serverURL, apiKey, name, cidr string) error {
	body := map[string]string{
		"name": name,
		"cidr": cidr,
	}
	data, _ := json.Marshal(body)

	req, _ := http.NewRequest("POST", serverURL+"/api/v1/networks", bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		CIDR string `json:"cidr"`
	}
	json.Unmarshal(respBody, &result)

	fmt.Printf("Network created: %s (ID: %s, CIDR: %s)\n", result.Name, result.ID, result.CIDR)
	return nil
}

// NetworkList lists networks via the API.
func NetworkList(serverURL, apiKey string) error {
	req, _ := http.NewRequest("GET", serverURL+"/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	var networks []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		CIDR string `json:"cidr"`
	}
	json.NewDecoder(resp.Body).Decode(&networks)

	if len(networks) == 0 {
		fmt.Println("No networks found.")
		return nil
	}

	fmt.Printf("%-36s  %-20s  %s\n", "ID", "NAME", "CIDR")
	for _, n := range networks {
		fmt.Printf("%-36s  %-20s  %s\n", n.ID, n.Name, n.CIDR)
	}
	return nil
}
