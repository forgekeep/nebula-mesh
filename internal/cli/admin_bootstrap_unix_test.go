//go:build unix

package cli

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/forgekeep/nebula-mesh/internal/api"
	"github.com/forgekeep/nebula-mesh/internal/keystore"
	"github.com/forgekeep/nebula-mesh/internal/store"
)

func TestAdminBootstrap_SEC_BOOTSTRAP_001_ExplicitKeyAuthenticates(t *testing.T) {
	dir := t.TempDir()
	var masterKey [keystore.MasterKeySize]byte
	_, err := rand.Read(masterKey[:])
	require.NoError(t, err)
	masterB64 := base64.StdEncoding.EncodeToString(masterKey[:])
	t.Setenv("NEBULA_MGMT_MASTER_KEY", masterB64)

	configPath := filepath.Join(dir, "server.yml")
	dbPath := filepath.Join(dir, "nebula.db")
	config := fmt.Sprintf("listen: 127.0.0.1:8080\ndata_dir: %q\ndb_path: %q\n", dir, dbPath)
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))
	require.NoError(t, Init(configPath))

	master, hasher, err := loadRuntimeKeys(masterB64)
	require.NoError(t, err)
	t.Cleanup(hasher.Destroy)
	s, err := store.NewSQLiteStore(dbPath, store.WithCredentialHasher(hasher), store.WithTOTPSecretMaster(master))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	admin, err := s.GetOperatorByUsername(t.Context(), DefaultAdminUsername)
	require.NoError(t, err)
	keys, err := s.ListOperatorAPIKeys(t.Context(), admin.ID)
	require.NoError(t, err)
	require.Empty(t, keys, "init must not issue an API key")

	private := filepath.Join(dir, "private")
	require.NoError(t, os.Mkdir(private, 0o700))
	output := filepath.Join(private, "admin.key")
	require.NoError(t, OpsMintAdminKey(configPath, output))
	credential, err := os.ReadFile(output)
	require.NoError(t, err)
	t.Cleanup(func() { clear(credential) })

	// Exercise the production bearer middleware and a read-only API route with
	// the issued credential. Never include it or the response in test output.
	srv := api.NewServer(s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/networks", nil)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(credential)))
	resp := httptest.NewRecorder()
	srv.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
}
