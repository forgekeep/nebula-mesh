package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
