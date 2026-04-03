package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// HostCreate creates a host via the API.
func HostCreate(serverURL, apiKey, networkID, name, nebulaIP, role string, groups []string, publicIP string, listenPort int) error {
	body := map[string]any{
		"network_id": networkID,
		"name":       name,
		"nebula_ip":  nebulaIP,
		"role":       role,
		"groups":     groups,
	}
	if publicIP != "" {
		body["public_ip"] = publicIP
	}
	if listenPort > 0 {
		body["listen_port"] = listenPort
	}

	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", serverURL+"/api/v1/hosts", bytes.NewReader(data))
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
		Host struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"host"`
		EnrollmentToken string `json:"enrollment_token"`
	}
	json.Unmarshal(respBody, &result)

	fmt.Printf("Host created: %s (ID: %s)\n", result.Host.Name, result.Host.ID)
	fmt.Printf("Enrollment token: %s\n", result.EnrollmentToken)
	return nil
}

// HostList lists hosts via the API.
func HostList(serverURL, apiKey, networkID string) error {
	url := serverURL + "/api/v1/hosts"
	if networkID != "" {
		url += "?network_id=" + networkID
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	var hosts []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		NebulaIP string `json:"nebula_ip"`
		Role     string `json:"role"`
		Status   string `json:"status"`
	}
	json.NewDecoder(resp.Body).Decode(&hosts)

	if len(hosts) == 0 {
		fmt.Println("No hosts found.")
		return nil
	}

	fmt.Printf("%-36s  %-20s  %-16s  %-12s  %s\n", "ID", "NAME", "NEBULA IP", "ROLE", "STATUS")
	for _, h := range hosts {
		fmt.Printf("%-36s  %-20s  %-16s  %-12s  %s\n", h.ID, h.Name, h.NebulaIP, h.Role, h.Status)
	}
	return nil
}
