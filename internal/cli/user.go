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

type userCreateRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role,omitempty"`
}

type userResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	Role        string `json:"role"`
}

// UserCreate creates a new operator via the API.
func UserCreate(serverURL, apiKey, username, password, displayName, role string) error {
	if username == "" || password == "" {
		return fmt.Errorf("--username and --password are required")
	}
	body, err := json.Marshal(userCreateRequest{ // #nosec G117 -- short-lived outbound API request body to the server's operator-create endpoint, not stored on disk
		Username: username, Password: password, DisplayName: displayName, Role: role,
	})
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, serverURL+"/api/v1/operators", bytes.NewReader(body))
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
	var out userResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("Operator created: %s (ID: %s)\n", out.Username, out.ID)
	return nil
}

// UserList lists operators via the API.
func UserList(serverURL, apiKey string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, serverURL+"/api/v1/operators", http.NoBody)
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
	var ops []userResponse
	if err := json.NewDecoder(resp.Body).Decode(&ops); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(ops) == 0 {
		fmt.Println("No operators found.")
		return nil
	}
	fmt.Printf("%-36s  %-20s  %-10s  %-10s  %s\n", "ID", "USERNAME", "STATUS", "ROLE", "DISPLAY NAME")
	for _, o := range ops {
		fmt.Printf("%-36s  %-20s  %-10s  %-10s  %s\n", o.ID, o.Username, o.Status, o.Role, o.DisplayName)
	}
	return nil
}

// UserDisable disables an operator via the API. Their sessions are
// invalidated and API keys revoked atomically.
func UserDisable(serverURL, apiKey, id string) error {
	return doHostAction(serverURL, apiKey, "POST", "/api/v1/operators/"+id+"/disable", http.StatusNoContent, "operator disabled")
}

// UserEnable re-enables a disabled operator.
func UserEnable(serverURL, apiKey, id string) error {
	return doHostAction(serverURL, apiKey, "POST", "/api/v1/operators/"+id+"/enable", http.StatusNoContent, "operator enabled")
}

type apiKeyCreateResponse struct {
	Key   string `json:"key"`
	Entry struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"entry"`
}

// APIKeyCreate creates a new per-operator API key. The plaintext key is
// printed once.
func APIKeyCreate(serverURL, apiKey, operatorID, name string) error {
	body, _ := json.Marshal(map[string]string{"name": name})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, serverURL+"/api/v1/operators/"+operatorID+"/api-keys", bytes.NewReader(body))
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
	var out apiKeyCreateResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	fmt.Printf("API key created (id: %s)\n", out.Entry.ID)
	fmt.Printf("Token (shown once): %s\n", out.Key)
	return nil
}

// APIKeyRevoke revokes an existing per-operator API key.
func APIKeyRevoke(serverURL, apiKey, operatorID, keyID string) error {
	return doHostAction(serverURL, apiKey, "DELETE", "/api/v1/operators/"+operatorID+"/api-keys/"+keyID, http.StatusNoContent, "api key revoked")
}
